package verifier

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// buildSyntheticELF constructs a valid 64-bit little-endian ELF binary in memory.
func buildSyntheticELF(execStack bool, hasCanary bool, hasFullRELRO bool, hasPartialRELRO bool) []byte {
	shstrtab := []byte("\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00")
	var dynstr []byte
	if hasCanary {
		dynstr = []byte("\x00__stack_chk_fail\x00")
	} else {
		dynstr = []byte("\x00other_function\x00")
	}

	// Dynamic symbol table (sym 0 is null, sym 1 is our symbol)
	dynsym := make([]byte, 48)
	// sym 1: st_name=1, st_info=0x12, st_other=0, st_shndx=0, st_value=0, st_size=0
	binary.LittleEndian.PutUint32(dynsym[24:28], 1)
	dynsym[28] = 0x12

	// Dynamic section
	var dynamicBuf bytes.Buffer
	if hasFullRELRO {
		// DT_BIND_NOW (24), val=0
		_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(24))
		_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(0))
		// DT_FLAGS_1 (0x6ffffffb), val=1 (DF_1_NOW)
		_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(0x6ffffffb))
		_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(1))
	} else if hasPartialRELRO {
		// No DT_BIND_NOW and no DF_1_NOW
	}
	// DT_NULL (0), val=0
	_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&dynamicBuf, binary.LittleEndian, uint64(0))
	dynamic := dynamicBuf.Bytes()

	ehSize := 64
	phentSize := 56
	shentSize := 64

	phCount := 3
	if !hasFullRELRO && !hasPartialRELRO {
		phCount = 2
	}

	phOffset := ehSize
	bodyOffset := phOffset + phCount*phentSize
	if bodyOffset%8 != 0 {
		bodyOffset += 8 - (bodyOffset % 8)
	}

	offShstrtab := bodyOffset
	offDynstr := offShstrtab + len(shstrtab)
	offDynsym := offDynstr + len(dynstr)
	if offDynsym%8 != 0 {
		offDynsym += 8 - (offDynsym % 8)
	}
	offDynamic := offDynsym + len(dynsym)
	if offDynamic%8 != 0 {
		offDynamic += 8 - (offDynamic % 8)
	}

	endData := offDynamic + len(dynamic)
	if endData%8 != 0 {
		endData += 8 - (endData % 8)
	}
	shOffset := endData
	shCount := 5

	var phsBuf bytes.Buffer
	// PH0: PT_LOAD (1), flags=5 (R-X)
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint32(5))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0x400000))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0x400000))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(endData))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(endData))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0x1000))

	// PH1: PT_GNU_STACK (0x6474e551), flags=7 (RWE) or 6 (RW-)
	stkFlags := uint32(6)
	if execStack {
		stkFlags = 7
	}
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint32(0x6474e551))
	_ = binary.Write(&phsBuf, binary.LittleEndian, stkFlags)
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(8))

	if hasFullRELRO || hasPartialRELRO {
		// PH2: PT_GNU_RELRO (0x6474e552), flags=4 (R--)
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint32(0x6474e552))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint32(4))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(offDynamic))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0x400000+uint64(offDynamic)))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(0x400000+uint64(offDynamic)))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(len(dynamic)))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(len(dynamic)))
		_ = binary.Write(&phsBuf, binary.LittleEndian, uint64(8))
	}
	phs := phsBuf.Bytes()

	// ELF Header
	var elfHdr bytes.Buffer
	elfHdr.WriteString("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(2))                 // e_type = ET_EXEC
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(62))                // e_machine = EM_X86_64
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint32(1))                 // e_version
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint64(0x400000))          // e_entry
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint64(phOffset))          // e_phoff
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint64(shOffset))          // e_shoff
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint32(0))                 // e_flags
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(ehSize))            // e_ehsize
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(phentSize))         // e_phentsize
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(phCount))           // e_phnum
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(shentSize))         // e_shentsize
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(shCount))           // e_shnum
	_ = binary.Write(&elfHdr, binary.LittleEndian, uint16(1))                 // e_shstrndx

	// Section headers:
	var shsBuf bytes.Buffer
	// SH0: NULL (64 bytes zeros)
	shsBuf.Write(make([]byte, 64))

	// SH1: .shstrtab (type 3 SHT_STRTAB)
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(offShstrtab))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(len(shstrtab)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(1))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0))

	// SH2: .dynstr (type 3 SHT_STRTAB)
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(11))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(2))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0x400000+uint64(offDynstr)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(offDynstr))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(len(dynstr)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(1))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0))

	// SH3: .dynsym (type 11 SHT_DYNSYM, link=2)
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(19))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(11))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(2))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0x400000+uint64(offDynsym)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(offDynsym))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(len(dynsym)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(2)) // link to .dynstr
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(1))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(8))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(24)) // ent size

	// SH4: .dynamic (type 6 SHT_DYNAMIC, link=2)
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(27))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(6))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(3))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(0x400000+uint64(offDynamic)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(offDynamic))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(len(dynamic)))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(2)) // link to .dynstr
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(8))
	_ = binary.Write(&shsBuf, binary.LittleEndian, uint64(16)) // ent size

	totalSize := shOffset + shCount*shentSize
	buf := make([]byte, totalSize)
	copy(buf[0:ehSize], elfHdr.Bytes())
	copy(buf[phOffset:phOffset+len(phs)], phs)
	copy(buf[offShstrtab:offShstrtab+len(shstrtab)], shstrtab)
	copy(buf[offDynstr:offDynstr+len(dynstr)], dynstr)
	copy(buf[offDynsym:offDynsym+len(dynsym)], dynsym)
	copy(buf[offDynamic:offDynamic+len(dynamic)], dynamic)
	copy(buf[shOffset:shOffset+shsBuf.Len()], shsBuf.Bytes())

	return buf
}

func TestVerifyELFHardeningInvariantsPasses(t *testing.T) {
	elfBytes := buildSyntheticELF(false, true, true, false)
	r := bytes.NewReader(elfBytes)

	report, err := VerifyELFHardeningReader(r, "test-hardened.elf")
	if err != nil {
		t.Fatalf("Expected fully hardened ELF to pass, got error: %v", err)
	}

	if !report.DefensesIntact {
		t.Errorf("Expected DefensesIntact == true")
	}
	if !report.StackNonExecutable {
		t.Errorf("Expected StackNonExecutable == true")
	}
	if !report.StackCanaryPresent {
		t.Errorf("Expected StackCanaryPresent == true")
	}
	if report.RELRO != RELROFull || !report.FullRELRO {
		t.Errorf("Expected Full RELRO, got %s", report.RELRO)
	}
}

func TestVerifyELFHardeningExecutableStackFails(t *testing.T) {
	// PT_GNU_STACK is executable (RWE)
	elfBytes := buildSyntheticELF(true, true, true, false)
	r := bytes.NewReader(elfBytes)

	report, err := VerifyELFHardeningReader(r, "test-execstack.elf")
	if err == nil {
		t.Fatalf("Expected executable stack to fail verification, but got nil error")
	}

	if !errors.Is(err, ErrCompilerDefenseAblated) {
		t.Errorf("Expected ErrCompilerDefenseAblated, got: %v", err)
	}

	if report.StackNonExecutable {
		t.Errorf("Expected StackNonExecutable == false for RWE stack")
	}
}

func TestVerifyELFHardeningStrippedCanaryFails(t *testing.T) {
	// Stack canary __stack_chk_fail missing
	elfBytes := buildSyntheticELF(false, false, true, false)
	r := bytes.NewReader(elfBytes)

	report, err := VerifyELFHardeningReader(r, "test-nocanary.elf")
	if err == nil {
		t.Fatalf("Expected missing stack canary to fail, but got nil error")
	}

	if !errors.Is(err, ErrCompilerDefenseAblated) {
		t.Errorf("Expected ErrCompilerDefenseAblated, got: %v", err)
	}

	if report.StackCanaryPresent {
		t.Errorf("Expected StackCanaryPresent == false")
	}
}

func TestVerifyELFHardeningPartialRELROFails(t *testing.T) {
	// Partial RELRO: PT_GNU_RELRO present but DT_BIND_NOW / DF_1_NOW missing
	elfBytes := buildSyntheticELF(false, true, false, true)
	r := bytes.NewReader(elfBytes)

	report, err := VerifyELFHardeningReader(r, "test-partialrelro.elf")
	if err == nil {
		t.Fatalf("Expected Partial RELRO to fail, but got nil error")
	}

	if !errors.Is(err, ErrCompilerDefenseAblated) {
		t.Errorf("Expected ErrCompilerDefenseAblated, got: %v", err)
	}

	if report.RELRO != RELROPartial {
		t.Errorf("Expected RELROPartial, got %s", report.RELRO)
	}
}

func TestCompareELFHardeningRegression(t *testing.T) {
	tmpDir := t.TempDir()
	baselineFile := filepath.Join(tmpDir, "baseline")
	targetFile := filepath.Join(tmpDir, "target")

	// Baseline has full defenses
	baselineData := buildSyntheticELF(false, true, true, false)
	if err := os.WriteFile(baselineFile, baselineData, 0755); err != nil {
		t.Fatalf("Failed to write baseline file: %v", err)
	}

	// Target stripped the stack canary
	targetData := buildSyntheticELF(false, false, true, false)
	if err := os.WriteFile(targetFile, targetData, 0755); err != nil {
		t.Fatalf("Failed to write target file: %v", err)
	}

	report, err := CompareELFHardening(baselineFile, targetFile)
	if err == nil {
		t.Fatalf("Expected regression comparison to fail, but got nil error")
	}

	if !errors.Is(err, ErrCompilerDefenseAblated) {
		t.Errorf("Expected ErrCompilerDefenseAblated, got: %v", err)
	}

	if report.DefensesIntact {
		t.Errorf("Expected target DefensesIntact == false")
	}
}
