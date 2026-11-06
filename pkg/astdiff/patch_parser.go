package astdiff

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// DiffLineType represents line change type in a diff.
type DiffLineType int

const (
	LineContext DiffLineType = iota
	LineAdded
	LineRemoved
)

// DiffLine captures a single line in a diff hunk.
type DiffLine struct {
	Type    DiffLineType
	Content string
	OldLine int
	NewLine int
}

// Hunk represents a unified diff hunk.
type Hunk struct {
	OldStartLine int
	OldLineCount int
	NewStartLine int
	NewLineCount int
	Lines        []DiffLine
}

// FileDiff represents changes for a single file in a unified diff.
type FileDiff struct {
	OldPath      string
	NewPath      string
	IsNew        bool
	IsDeleted    bool
	Hunks        []Hunk
	AddedLines   map[int]string
	RemovedLines map[int]string
}

// ParsePatch parses a unified diff / git diff into a slice of FileDiff.
func ParsePatch(data []byte) ([]*FileDiff, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var files []*FileDiff
	var currentFile *FileDiff
	var currentHunk *Hunk

	oldLine := 0
	newLine := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Diff headers
		if strings.HasPrefix(line, "diff --git ") {
			if currentFile != nil {
				if currentHunk != nil {
					currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
					currentHunk = nil
				}
				files = append(files, currentFile)
			}
			parts := strings.Split(line, " ")
			oldPath := ""
			newPath := ""
			if len(parts) >= 4 {
				oldPath = strings.TrimPrefix(parts[2], "a/")
				newPath = strings.TrimPrefix(parts[3], "b/")
			}
			currentFile = &FileDiff{
				OldPath:      oldPath,
				NewPath:      newPath,
				AddedLines:   make(map[int]string),
				RemovedLines: make(map[int]string),
			}
			continue
		}

		if strings.HasPrefix(line, "--- ") {
			path := strings.TrimPrefix(line, "--- ")
			path = strings.TrimPrefix(path, "a/")
			if path == "/dev/null" {
				if currentFile != nil {
					currentFile.IsNew = true
				}
			} else if currentFile != nil && currentFile.OldPath == "" {
				currentFile.OldPath = strings.Fields(path)[0]
			}
			continue
		}

		if strings.HasPrefix(line, "+++ ") {
			path := strings.TrimPrefix(line, "+++ ")
			path = strings.TrimPrefix(path, "b/")
			if path == "/dev/null" {
				if currentFile != nil {
					currentFile.IsDeleted = true
				}
			} else if currentFile != nil {
				currentFile.NewPath = strings.Fields(path)[0]
			}
			continue
		}

		// Hunk header: @@ -oldStart,oldCount +newStart,newCount @@
		if strings.HasPrefix(line, "@@ ") {
			if currentFile == nil {
				currentFile = &FileDiff{
					AddedLines:   make(map[int]string),
					RemovedLines: make(map[int]string),
				}
			}
			if currentHunk != nil {
				currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
			}

			hunk, err := parseHunkHeader(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse hunk header %q: %w", line, err)
			}
			currentHunk = hunk
			oldLine = hunk.OldStartLine
			newLine = hunk.NewStartLine
			continue
		}

		if currentHunk == nil {
			continue
		}

		// Hunk content line
		if len(line) == 0 {
			// Empty line treated as empty context
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    LineContext,
				Content: "",
				OldLine: oldLine,
				NewLine: newLine,
			})
			oldLine++
			newLine++
			continue
		}

		switch line[0] {
		case '+':
			content := line[1:]
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    LineAdded,
				Content: content,
				NewLine: newLine,
			})
			if currentFile != nil {
				currentFile.AddedLines[newLine] = content
			}
			newLine++
		case '-':
			content := line[1:]
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    LineRemoved,
				Content: content,
				OldLine: oldLine,
			})
			if currentFile != nil {
				currentFile.RemovedLines[oldLine] = content
			}
			oldLine++
		case ' ':
			content := line[1:]
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:    LineContext,
				Content: content,
				OldLine: oldLine,
				NewLine: newLine,
			})
			oldLine++
			newLine++
		default:
			// No newline at end of file, etc.
			continue
		}
	}

	if currentFile != nil {
		if currentHunk != nil {
			currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
		}
		files = append(files, currentFile)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading diff patch: %w", err)
	}

	return files, nil
}

func parseHunkHeader(header string) (*Hunk, error) {
	// e.g. "@@ -1,5 +1,6 @@ optional header"
	parts := strings.Split(header, "@@")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid hunk header format")
	}
	rangeSpec := strings.TrimSpace(parts[1])
	ranges := strings.Split(rangeSpec, " ")
	if len(ranges) < 2 {
		return nil, fmt.Errorf("invalid range spec: %s", rangeSpec)
	}

	oldSpec := strings.TrimPrefix(ranges[0], "-")
	newSpec := strings.TrimPrefix(ranges[1], "+")

	oldStart, oldCount, err := parseRange(oldSpec)
	if err != nil {
		return nil, err
	}
	newStart, newCount, err := parseRange(newSpec)
	if err != nil {
		return nil, err
	}

	return &Hunk{
		OldStartLine: oldStart,
		OldLineCount: oldCount,
		NewStartLine: newStart,
		NewLineCount: newCount,
		Lines:        make([]DiffLine, 0),
	}, nil
}

func parseRange(spec string) (start int, count int, err error) {
	if strings.Contains(spec, ",") {
		sub := strings.Split(spec, ",")
		start, err = strconv.Atoi(sub[0])
		if err != nil {
			return 0, 0, err
		}
		count, err = strconv.Atoi(sub[1])
		if err != nil {
			return 0, 0, err
		}
		return start, count, nil
	}
	start, err = strconv.Atoi(spec)
	if err != nil {
		return 0, 0, err
	}
	return start, 1, nil
}
