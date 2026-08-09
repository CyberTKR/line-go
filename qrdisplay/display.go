package qrdisplay

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	qrcode "github.com/skip2/go-qrcode"
)

func Render(content, outputPath string, stream io.Writer, quiet bool) (string, error) {
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("QR could not be generated: %w", err)
	}
	absolute, err := filepath.Abs(outputPath)
	if err != nil {
		return "", err
	}
	if err := code.WriteFile(384, absolute); err != nil {
		return "", fmt.Errorf("QR PNG could not be written: %w", err)
	}
	if !quiet {
		if stream == nil {
			stream = os.Stdout
		}
		fmt.Fprintln(stream)
		fmt.Fprintln(stream, "[QR] Scan with LINE:")
		fmt.Fprintln(stream)
		printTerminal(stream, code.Bitmap())
	}
	return absolute, nil
}

func printTerminal(output io.Writer, bitmap [][]bool) {
	for y := 0; y < len(bitmap); y += 2 {
		for x := range bitmap[y] {
			top := bitmap[y][x]
			bottom := y+1 < len(bitmap) && bitmap[y+1][x]
			symbol := "  "
			switch {
			case top && bottom:
				symbol = "██"
			case top:
				symbol = "▀▀"
			case bottom:
				symbol = "▄▄"
			}
			fmt.Fprint(output, symbol)
		}
		fmt.Fprintln(output)
	}
}
