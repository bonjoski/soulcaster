package verifier

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrCompilerDefenseAblated indicates that compiler hardening defenses (stack canary, non-executable stack, Full RELRO)
// were stripped, degraded, or disabled in the compiled binary.
var ErrCompilerDefenseAblated = errors.New("ERR_COMPILER_DEFENSE_ABLATED")

// RELROLevel describes the relocation read-only protection status.
type RELROLevel string

const (
	RELROFull    RELROLevel = "FULL"
	RELROPartial RELROLevel = "PARTIAL"
	RELRONone    RELROLevel = "NONE"
)

// HardeningReport records the compiler hardening status of an ELF binary.
type HardeningReport struct {
	BinaryPath         string     `json:"binaryPath"`
	IsELF              bool       `json:"isElf"`
	GNUStackPresent    bool       `json:"gnuStackPresent"`
	StackNonExecutable bool       `json:"stackNonExecutable"`
	StackCanaryPresent bool       `json:"stackCanaryPresent"`
	RELRO              RELROLevel `json:"relro"`
	FullRELRO          bool       `json:"fullRelro"`
	DefensesIntact     bool       `json:"defensesIntact"`
	Violations         []string   `json:"violations,omitempty"`
}

// VerifyELFHardeningInvariants inspects an ELF binary file on disk for required compiler hardening flags:
// 1. PT_GNU_STACK must be non-executable (RW-, not RWE).
// 2. Symbol __stack_chk_fail must be present in dynamic/imported symbols.
// 3. Full RELRO (PT_GNU_RELRO + DT_BIND_NOW / DF_1_NOW) must be preserved.
// If any defense is missing or ablated, returns an error wrapping ErrCompilerDefenseAblated.
func VerifyELFHardeningInvariants(path string) (*HardeningReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary %s: %w", path, err)
	}
	defer f.Close()

	return VerifyELFHardeningReader(f, path)
}

// VerifyELFHardeningReader inspects ELF binary data from an io.ReaderAt.
func VerifyELFHardeningReader(r io.ReaderAt, name string) (*HardeningReport, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file %s: %w", name, err)
	}
	defer elfFile.Close()

	report := &HardeningReport{
		BinaryPath: name,
		IsELF:      true,
		Violations: make([]string, 0),
	}

	// 1. Inspect PT_GNU_STACK
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			report.GNUStackPresent = true
			if (prog.Flags & elf.PF_X) == 0 {
				report.StackNonExecutable = true
			}
			break
		}
	}

	if !report.GNUStackPresent {
		report.Violations = append(report.Violations, "PT_GNU_STACK program header is missing")
	} else if !report.StackNonExecutable {
		report.Violations = append(report.Violations, "PT_GNU_STACK is executable (RWE); non-executable stack defense ablated")
	}

	// 2. Inspect stack canary: __stack_chk_fail in dynamic / imported / static symbols
	report.StackCanaryPresent = hasStackCanarySymbol(elfFile)
	if !report.StackCanaryPresent {
		report.Violations = append(report.Violations, "Symbol __stack_chk_fail is missing from dynamic/symbol table; stack canary defense ablated")
	}

	// 3. Inspect Full RELRO: PT_GNU_RELRO + DT_BIND_NOW / DF_1_NOW
	hasGNURelro := false
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasGNURelro = true
			break
		}
	}

	hasBindNow := checkBindNow(elfFile)

	if hasGNURelro && hasBindNow {
		report.RELRO = RELROFull
		report.FullRELRO = true
	} else if hasGNURelro {
		report.RELRO = RELROPartial
		report.FullRELRO = false
		report.Violations = append(report.Violations, "Partial RELRO detected: DT_BIND_NOW / DF_1_NOW is missing; Full RELRO defense ablated")
	} else {
		report.RELRO = RELRONone
		report.FullRELRO = false
		report.Violations = append(report.Violations, "PT_GNU_RELRO program header is missing; RELRO defense ablated")
	}

	report.DefensesIntact = len(report.Violations) == 0

	if !report.DefensesIntact {
		return report, fmt.Errorf("%w: %s", ErrCompilerDefenseAblated, strings.Join(report.Violations, "; "))
	}

	return report, nil
}

// CompareELFHardening compares a baseline binary against a target binary, ensuring defenses were not downgraded.
func CompareELFHardening(baselinePath, targetPath string) (*HardeningReport, error) {
	baselineReport, err := VerifyELFHardeningInvariants(baselinePath)
	if err != nil && !errors.Is(err, ErrCompilerDefenseAblated) {
		return nil, fmt.Errorf("failed to evaluate baseline binary %s: %w", baselinePath, err)
	}

	targetReport, err := VerifyELFHardeningInvariants(targetPath)
	if err != nil && !errors.Is(err, ErrCompilerDefenseAblated) {
		return nil, fmt.Errorf("failed to evaluate target binary %s: %w", targetPath, err)
	}

	var regressionViolations []string

	if baselineReport != nil && targetReport != nil {
		if baselineReport.StackNonExecutable && !targetReport.StackNonExecutable {
			regressionViolations = append(regressionViolations, "Stack execution permissions downgraded from non-executable (RW-) to executable (RWE)")
		}
		if baselineReport.StackCanaryPresent && !targetReport.StackCanaryPresent {
			regressionViolations = append(regressionViolations, "Stack canary (__stack_chk_fail) was removed in target binary")
		}
		if baselineReport.FullRELRO && !targetReport.FullRELRO {
			regressionViolations = append(regressionViolations, fmt.Sprintf("RELRO downgraded from FULL to %s", targetReport.RELRO))
		}
	}

	if len(regressionViolations) > 0 {
		targetReport.Violations = append(targetReport.Violations, regressionViolations...)
		targetReport.DefensesIntact = false
		return targetReport, fmt.Errorf("%w: %s", ErrCompilerDefenseAblated, strings.Join(regressionViolations, "; "))
	}

	if err != nil {
		return targetReport, err
	}

	return targetReport, nil
}

func hasStackCanarySymbol(f *elf.File) bool {
	// 1. Check dynamic symbols
	if dynSyms, err := f.DynamicSymbols(); err == nil {
		for _, s := range dynSyms {
			if s.Name == "__stack_chk_fail" {
				return true
			}
		}
	}

	// 2. Check imported symbols
	if impSyms, err := f.ImportedSymbols(); err == nil {
		for _, s := range impSyms {
			if s.Name == "__stack_chk_fail" {
				return true
			}
		}
	}

	// 3. Check static symbols if present
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "__stack_chk_fail" {
				return true
			}
		}
	}

	return false
}

func checkBindNow(f *elf.File) bool {
	// Check DT_BIND_NOW
	if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		return true
	}

	// Check DT_FLAGS_1 (0x6ffffffb) for DF_1_NOW (0x1)
	if vals, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if (v & 0x1) != 0 {
				return true
			}
		}
	}

	// Check DT_FLAGS (0x1e) for DF_BIND_NOW (0x8)
	if vals, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range vals {
			if (v & 0x8) != 0 {
				return true
			}
		}
	}

	// Fallback: manually parse .dynamic section if DynValue fails on synthetic files
	if sec := f.Section(".dynamic"); sec != nil {
		data, err := sec.Data()
		if err == nil {
			entrySize := 16 // 64-bit Elf64_Dyn: d_tag (8 bytes), d_val/d_ptr (8 bytes)
			if f.Class == elf.ELFCLASS32 {
				entrySize = 8
			}
			for i := 0; i+entrySize <= len(data); i += entrySize {
				var tag uint64
				var val uint64
				if f.Class == elf.ELFCLASS32 {
					tag = uint64(f.ByteOrder.Uint32(data[i : i+4]))
					val = uint64(f.ByteOrder.Uint32(data[i+4 : i+8]))
				} else {
					tag = f.ByteOrder.Uint64(data[i : i+8])
					val = f.ByteOrder.Uint64(data[i+8 : i+16])
				}
				if elf.DynTag(tag) == elf.DT_BIND_NOW {
					return true
				}
				if elf.DynTag(tag) == elf.DT_FLAGS_1 && (val&0x1) != 0 {
					return true
				}
				if elf.DynTag(tag) == elf.DT_FLAGS && (val&0x8) != 0 {
					return true
				}
			}
		}
	}

	return false
}
