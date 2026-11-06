package astdiff

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
)

// GoAnalyzer performs differential AST security analysis on Go code.
type GoAnalyzer struct{}

func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{}
}

func (ga *GoAnalyzer) Language() string {
	return "go"
}

func (ga *GoAnalyzer) CanAnalyze(filename string) bool {
	return filepath.Ext(filename) == ".go"
}

// AuthCheckRecord captures an authorization check in a function.
type AuthCheckRecord struct {
	CalleeName string
	Snippet    string
	Line       int
	Enclosing  string
	IsBypassed bool
}

// MemoryConstructRecord captures a dangerous memory construct.
type MemoryConstructRecord struct {
	Kind    string
	Snippet string
	Line    int
}

// ErrorSwallowRecord captures an error swallowing construct.
type ErrorSwallowRecord struct {
	Kind    string
	Snippet string
	Line    int
}

// AnalyzeSources compares base and head Go source code and reports violations.
func (ga *GoAnalyzer) AnalyzeSources(filename string, baseSource, headSource []byte, fileDiff *FileDiff) ([]Violation, error) {
	var violations []Violation

	fsetBase := token.NewFileSet()
	fsetHead := token.NewFileSet()

	var baseAST *ast.File
	var headAST *ast.File
	var err error

	if len(baseSource) > 0 {
		baseAST, err = parser.ParseFile(fsetBase, filename, baseSource, parser.ParseComments)
		if err != nil {
			// If base file had syntax error, parse what we can or proceed
			baseAST = nil
		}
	}

	if len(headSource) > 0 {
		headAST, err = parser.ParseFile(fsetHead, filename, headSource, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("failed to parse head Go source for %s: %w", filename, err)
		}
	}

	// If head was deleted, no secondary flaw introduced
	if headAST == nil {
		return violations, nil
	}

	// 1. RULE SEC-AST-001: Removed Authorization Checks
	if baseAST != nil {
		baseAuthChecks := extractAuthChecks(fsetBase, baseAST, baseSource)
		headAuthChecks := extractAuthChecks(fsetHead, headAST, headSource)

		removedAuth := findRemovedAuthChecks(baseAuthChecks, headAuthChecks, headAST)
		for _, r := range removedAuth {
			// Only flag if enclosing function still exists in head
			violations = append(violations, Violation{
				RuleID:      RuleRemovedAuthCheck,
				RuleName:    "RemovedAuthCheck",
				Severity:    SeverityCritical,
				File:        filename,
				Line:        r.Line,
				Function:    r.Enclosing,
				Message:     fmt.Sprintf("Authorization check %q present in base was removed or bypassed in patch", r.CalleeName),
				BaseSnippet: r.Snippet,
				ASTNodeType: "CallExpr",
				Metadata: map[string]string{
					"callee": r.CalleeName,
				},
			})
		}

		// Also check if any auth check in head was deliberately bypassed
		for _, h := range headAuthChecks {
			if h.IsBypassed {
				violations = append(violations, Violation{
					RuleID:      RuleRemovedAuthCheck,
					RuleName:    "RemovedAuthCheck",
					Severity:    SeverityCritical,
					File:        filename,
					Line:        h.Line,
					Function:    h.Enclosing,
					Message:     fmt.Sprintf("Authorization check %q in %s is bypassed via short-circuit or constant false", h.CalleeName, h.Enclosing),
					HeadSnippet: h.Snippet,
					ASTNodeType: "CallExpr",
					Metadata: map[string]string{
						"bypassed": "true",
						"callee":   h.CalleeName,
					},
				})
			}
		}
	}

	// 2. RULE SEC-AST-002: Swallowed Errors
	headSwallows := extractErrorSwallows(fsetHead, headAST, headSource)
	var baseSwallows []ErrorSwallowRecord
	if baseAST != nil {
		baseSwallows = extractErrorSwallows(fsetBase, baseAST, baseSource)
	}

	for _, hs := range headSwallows {
		if !containsMatchingSwallow(baseSwallows, hs) {
			// If fileDiff provided, verify it is in an added line or hunk
			if fileDiff != nil && len(fileDiff.AddedLines) > 0 {
				if _, ok := fileDiff.AddedLines[hs.Line]; !ok {
					// Check nearby lines in hunk (+/- 1 line)
					if _, okMinus := fileDiff.AddedLines[hs.Line-1]; !okMinus {
						if _, okPlus := fileDiff.AddedLines[hs.Line+1]; !okPlus {
							continue
						}
					}
				}
			}

			violations = append(violations, Violation{
				RuleID:      RuleErrorSwallowed,
				RuleName:    "ErrorSwallowed",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hs.Line,
				Message:     fmt.Sprintf("Swallowed error detected via %s: %s", hs.Kind, hs.Snippet),
				HeadSnippet: hs.Snippet,
				ASTNodeType: hs.Kind,
			})
		}
	}

	// 3. RULE SEC-AST-003: Dangerous Memory and Pointer Constructs
	headMemory := extractDangerousMemory(fsetHead, headAST, headSource)
	var baseMemory []MemoryConstructRecord
	if baseAST != nil {
		baseMemory = extractDangerousMemory(fsetBase, baseAST, baseSource)
	}

	for _, hm := range headMemory {
		if !containsMatchingMemory(baseMemory, hm) {
			if fileDiff != nil && len(fileDiff.AddedLines) > 0 {
				if _, ok := fileDiff.AddedLines[hm.Line]; !ok {
					if _, okMinus := fileDiff.AddedLines[hm.Line-1]; !okMinus {
						if _, okPlus := fileDiff.AddedLines[hm.Line+1]; !okPlus {
							continue
						}
					}
				}
			}

			violations = append(violations, Violation{
				RuleID:      RuleDangerousMemory,
				RuleName:    "DangerousMemoryConstruct",
				Severity:    SeverityHigh,
				File:        filename,
				Line:        hm.Line,
				Message:     fmt.Sprintf("Dangerous pointer or memory construct introduced: %s (%s)", hm.Snippet, hm.Kind),
				HeadSnippet: hm.Snippet,
				ASTNodeType: hm.Kind,
			})
		}
	}

	return violations, nil
}

// extractAuthChecks locates all authorization and permission checks in the AST.
func extractAuthChecks(fset *token.FileSet, file *ast.File, src []byte) []AuthCheckRecord {
	var records []AuthCheckRecord
	var currentFunc string

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			currentFunc = node.Name.Name
			if node.Recv != nil && len(node.Recv.List) > 0 {
				recvType := exprToString(node.Recv.List[0].Type)
				currentFunc = fmt.Sprintf("%s.%s", recvType, node.Name.Name)
			}
		case *ast.CallExpr:
			if ok, name := isAuthCallOrMiddleware(node); ok {
				pos := fset.Position(node.Pos())
				snippet := nodeToSnippet(fset, node, src)
				bypassed := isCallBypassed(node)

				records = append(records, AuthCheckRecord{
					CalleeName: name,
					Snippet:    snippet,
					Line:       pos.Line,
					Enclosing:  currentFunc,
					IsBypassed: bypassed,
				})
			}
		case *ast.IfStmt:
			// Check if condition contains bypassed auth
			if isBypassedAuthIf(node) {
				pos := fset.Position(node.Pos())
				records = append(records, AuthCheckRecord{
					CalleeName: "BypassedAuthCondition",
					Snippet:    nodeToSnippet(fset, node.Cond, src),
					Line:       pos.Line,
					Enclosing:  currentFunc,
					IsBypassed: true,
				})
			}
		}
		return true
	})

	return records
}

func isAuthCallOrMiddleware(call *ast.CallExpr) (bool, string) {
	callee := exprToString(call.Fun)
	if isAuthCheckName(callee) {
		return true, callee
	}

	lower := strings.ToLower(callee)
	// Check router middleware chaining: r.Use(...) or router.Use(...)
	if strings.HasSuffix(lower, ".use") || lower == "use" {
		for _, arg := range call.Args {
			argStr := exprToString(arg)
			if isAuthCheckName(argStr) {
				return true, fmt.Sprintf("%s(%s)", callee, argStr)
			}
		}
	}

	return false, ""
}

func isAuthCheckName(callee string) bool {
	lower := strings.ToLower(callee)
	keywords := []string{
		"auth", "jwt", "token", "guard",
		"authorize", "authorized", "isauthorized", "is_authorized",
		"authenticate", "authenticated", "isauthenticated", "is_authenticated",
		"verifytoken", "validatetoken", "checktoken", "parsetoken",
		"checkpermission", "haspermission", "requirepermission",
		"checkrole", "hasrole", "requirerole", "requireadmin", "requireauth",
		"checkaccess", "canaccess", "verifyaccess",
		"isallowed", "checkallowed",
		"casbin.enforce", "enforce", "rbac", "guard.check",
	}

	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	// Middleware patterns: r.Use(...) or router.Use(...) with auth middleware
	if strings.HasSuffix(lower, ".use") || lower == "use" {
		if strings.Contains(lower, "auth") || strings.Contains(lower, "jwt") || strings.Contains(lower, "token") {
			return true
		}
	}

	return false
}

func isCallBypassed(call *ast.CallExpr) bool {
	return false
}

func isBypassedAuthIf(ifStmt *ast.IfStmt) bool {
	// Check for e.g. "if false && isAuthorized(...)" or "if false { ... auth ... }"
	if bin, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
		if bin.Op == token.LAND {
			if ident, ok := bin.X.(*ast.Ident); ok && ident.Name == "false" {
				return true
			}
		}
		if bin.Op == token.LOR {
			if ident, ok := bin.X.(*ast.Ident); ok && ident.Name == "true" {
				return true
			}
		}
	}
	return false
}

// findRemovedAuthChecks identifies auth checks present in base but missing in head.
func findRemovedAuthChecks(base, head []AuthCheckRecord, headAST *ast.File) []AuthCheckRecord {
	var removed []AuthCheckRecord

	// Map head functions to their auth check callees
	headFuncAuth := make(map[string][]string)
	for _, h := range head {
		if !h.IsBypassed {
			headFuncAuth[h.Enclosing] = append(headFuncAuth[h.Enclosing], h.CalleeName)
		}
	}

	// Find which functions still exist in head AST
	headFunctions := make(map[string]bool)
	ast.Inspect(headAST, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				recvType := exprToString(fn.Recv.List[0].Type)
				name = fmt.Sprintf("%s.%s", recvType, fn.Name.Name)
			}
			headFunctions[name] = true
		}
		return true
	})

	for _, b := range base {
		// If enclosing function was removed entirely, that's not dropping auth inside an existing endpoint
		if b.Enclosing != "" && !headFunctions[b.Enclosing] {
			continue
		}

		headCallees, ok := headFuncAuth[b.Enclosing]
		if !ok || len(headCallees) == 0 {
			// Enclosing function exists, but has ZERO auth checks now!
			removed = append(removed, b)
		}
	}

	return removed
}

// extractErrorSwallows finds swallowed errors in the AST.
func extractErrorSwallows(fset *token.FileSet, file *ast.File, src []byte) []ErrorSwallowRecord {
	var records []ErrorSwallowRecord

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Check for blank assignment: _ = err or _, _ = ...
			for i, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "_" {
					// Check corresponding RHS
					if i < len(node.Rhs) {
						rhs := node.Rhs[i]
						if isErrorExpression(rhs) {
							pos := fset.Position(node.Pos())
							records = append(records, ErrorSwallowRecord{
								Kind:    "AssignStmt",
								Snippet: nodeToSnippet(fset, node, src),
								Line:    pos.Line,
							})
						}
					}
				}
			}

		case *ast.IfStmt:
			// Check for empty if err != nil {}
			if isErrCheckCondition(node.Cond) {
				if isEmptyBlock(node.Body) {
					pos := fset.Position(node.Pos())
					records = append(records, ErrorSwallowRecord{
						Kind:    "EmptyIfErrBlock",
						Snippet: nodeToSnippet(fset, node, src),
						Line:    pos.Line,
					})
				}
			}

		case *ast.DeferStmt:
			// Check for bare recover() inside defer
			if isBareRecover(node.Call) {
				pos := fset.Position(node.Pos())
				records = append(records, ErrorSwallowRecord{
					Kind:    "BareRecover",
					Snippet: nodeToSnippet(fset, node, src),
					Line:    pos.Line,
				})
			}
		}
		return true
	})

	return records
}

func isErrorExpression(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		name := strings.ToLower(e.Name)
		return name == "err" || name == "error" || strings.HasPrefix(name, "err") || strings.HasSuffix(name, "err")
	case *ast.CallExpr:
		callee := strings.ToLower(exprToString(e.Fun))
		if callee == "recover" {
			return true
		}
	}
	return false
}

func isErrCheckCondition(cond ast.Expr) bool {
	if bin, ok := cond.(*ast.BinaryExpr); ok {
		if bin.Op == token.NEQ {
			// e.g. err != nil
			xStr := strings.ToLower(exprToString(bin.X))
			yStr := strings.ToLower(exprToString(bin.Y))
			if (strings.Contains(xStr, "err") && yStr == "nil") || (strings.Contains(yStr, "err") && xStr == "nil") {
				return true
			}
		}
	}
	return false
}

func isEmptyBlock(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return true
	}
	// If only contains blank no-op expression like `_ = 0`
	if len(block.List) == 1 {
		if assign, ok := block.List[0].(*ast.AssignStmt); ok {
			if len(assign.Lhs) == 1 {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name == "_" {
					return true
				}
			}
		}
	}
	return false
}

func isBareRecover(call *ast.CallExpr) bool {
	callee := exprToString(call.Fun)
	if callee == "recover" {
		return true
	}
	// Check if call is an anonymous func call: func() { recover() }()
	if fnLit, ok := call.Fun.(*ast.FuncLit); ok {
		if fnLit.Body != nil {
			for _, stmt := range fnLit.Body.List {
				if exprStmt, ok := stmt.(*ast.ExprStmt); ok {
					if c, ok := exprStmt.X.(*ast.CallExpr); ok {
						if exprToString(c.Fun) == "recover" {
							return true
						}
					}
				}
				if assign, ok := stmt.(*ast.AssignStmt); ok {
					for _, rhs := range assign.Rhs {
						if c, ok := rhs.(*ast.CallExpr); ok {
							if exprToString(c.Fun) == "recover" {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// extractDangerousMemory locates unsafe and pointer arithmetic operations.
func extractDangerousMemory(fset *token.FileSet, file *ast.File, src []byte) []MemoryConstructRecord {
	var records []MemoryConstructRecord

	unsafeAlias := "unsafe"
	reflectAlias := "reflect"
	hasDotUnsafe := false

	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "unsafe" {
			if imp.Name != nil {
				if imp.Name.Name == "." {
					hasDotUnsafe = true
				} else {
					unsafeAlias = imp.Name.Name
				}
			}
		}
		if path == "reflect" {
			if imp.Name != nil {
				reflectAlias = imp.Name.Name
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if hasDotUnsafe && (node.Name == "Pointer" || node.Name == "Slice" || node.Name == "String") {
				pos := fset.Position(node.Pos())
				records = append(records, MemoryConstructRecord{
					Kind:    fmt.Sprintf("unsafe.%s", node.Name),
					Snippet: nodeToSnippet(fset, node, src),
					Line:    pos.Line,
				})
			}

		case *ast.SelectorExpr:
			xStr := exprToString(node.X)
			selStr := node.Sel.Name
			if xStr == unsafeAlias || xStr == "unsafe" {
				pos := fset.Position(node.Pos())
				records = append(records, MemoryConstructRecord{
					Kind:    fmt.Sprintf("unsafe.%s", selStr),
					Snippet: nodeToSnippet(fset, node, src),
					Line:    pos.Line,
				})
			} else if (xStr == reflectAlias || xStr == "reflect" || strings.HasSuffix(xStr, ".reflect")) &&
				(selStr == "SliceHeader" || selStr == "StringHeader") {
				pos := fset.Position(node.Pos())
				records = append(records, MemoryConstructRecord{
					Kind:    fmt.Sprintf("reflect.%s", selStr),
					Snippet: nodeToSnippet(fset, node, src),
					Line:    pos.Line,
				})
			}

		case *ast.BinaryExpr:
			// Check for pointer arithmetic with uintptr
			if node.Op == token.ADD || node.Op == token.SUB {
				xStr := exprToString(node.X)
				yStr := exprToString(node.Y)
				if strings.Contains(xStr, "uintptr") || strings.Contains(yStr, "uintptr") {
					pos := fset.Position(node.Pos())
					records = append(records, MemoryConstructRecord{
						Kind:    "uintptr-arithmetic",
						Snippet: nodeToSnippet(fset, node, src),
						Line:    pos.Line,
					})
				}
			}
		}
		return true
	})

	return records
}

func containsMatchingSwallow(baseList []ErrorSwallowRecord, target ErrorSwallowRecord) bool {
	for _, b := range baseList {
		if b.Kind == target.Kind && strings.TrimSpace(b.Snippet) == strings.TrimSpace(target.Snippet) {
			return true
		}
	}
	return false
}

func containsMatchingMemory(baseList []MemoryConstructRecord, target MemoryConstructRecord) bool {
	for _, b := range baseList {
		if b.Kind == target.Kind && strings.TrimSpace(b.Snippet) == strings.TrimSpace(target.Snippet) {
			return true
		}
	}
	return false
}

func exprToString(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		xStr := exprToString(e.X)
		if xStr != "" {
			return xStr + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.CallExpr:
		funStr := exprToString(e.Fun)
		var args []string
		for _, arg := range e.Args {
			args = append(args, exprToString(arg))
		}
		return fmt.Sprintf("%s(%s)", funStr, strings.Join(args, ", "))
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.UnaryExpr:
		return e.Op.String() + exprToString(e.X)
	case *ast.BinaryExpr:
		return exprToString(e.X) + " " + e.Op.String() + " " + exprToString(e.Y)
	default:
		var buf bytes.Buffer
		_ = printer.Fprint(&buf, token.NewFileSet(), expr)
		return buf.String()
	}
}

func nodeToSnippet(fset *token.FileSet, node ast.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if len(src) > 0 {
		start := fset.Position(node.Pos()).Offset
		end := fset.Position(node.End()).Offset
		if start >= 0 && end <= len(src) && start < end {
			return string(src[start:end])
		}
	}
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, node)
	return buf.String()
}
