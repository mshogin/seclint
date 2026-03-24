package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/mikeshogin/seclint/pkg/classifier"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: seclint {rate|check|serve}\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  rate              Rate prompt content from stdin\n")
		fmt.Fprintf(os.Stderr, "  check --max-rating N  Check if prompt passes threshold (exit 0=pass, 1=fail)\n")
		fmt.Fprintf(os.Stderr, "  serve [port]      Start HTTP server (default: 8091)\n")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "rate":
		runRate()
	case "check":
		runCheck()
	case "serve":
		runServe()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func runRate() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	result := classifier.Classify(string(input))
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

func runCheck() {
	maxRating := classifier.Rating16Plus // default
	for i, arg := range os.Args[2:] {
		if arg == "--max-rating" && i+3 < len(os.Args) {
			val := os.Args[i+3]
			n, err := strconv.Atoi(val)
			if err == nil {
				switch {
				case n <= 6:
					maxRating = classifier.Rating6Plus
				case n <= 12:
					maxRating = classifier.Rating12Plus
				case n <= 16:
					maxRating = classifier.Rating16Plus
				default:
					maxRating = classifier.Rating18Plus
				}
			}
		}
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if classifier.IsSafe(string(input), maxRating) {
		result := classifier.Classify(string(input))
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		os.Exit(0)
	} else {
		result := classifier.Classify(string(input))
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stderr, string(out))
		os.Exit(1)
	}
}

func runServe() {
	port := "8091"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	fmt.Fprintf(os.Stderr, "seclint server on :%s\n", port)

	http.HandleFunc("/rate", handleRate)
	http.HandleFunc("/check", handleCheck)
	http.HandleFunc("/health", handleHealth)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func handleRate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	result := classifier.Classify(string(body))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	maxRatingStr := r.URL.Query().Get("max_rating")
	maxRating := classifier.Rating16Plus
	if n, err := strconv.Atoi(maxRatingStr); err == nil {
		switch {
		case n <= 6:
			maxRating = classifier.Rating6Plus
		case n <= 12:
			maxRating = classifier.Rating12Plus
		case n <= 16:
			maxRating = classifier.Rating16Plus
		default:
			maxRating = classifier.Rating18Plus
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	result := classifier.Classify(string(body))
	safe := classifier.IsSafe(string(body), maxRating)

	response := map[string]interface{}{
		"result": result,
		"safe":   safe,
	}

	w.Header().Set("Content-Type", "application/json")
	if !safe {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"status":"ok"}`))
}
