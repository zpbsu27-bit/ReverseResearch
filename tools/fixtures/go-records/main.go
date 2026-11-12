package main

import "example.invalid/rr/local"

// This owned producer target is inspected, never executed by the workflow.
var BuildLabel = "unmodified"

func main() { println(local.Label, BuildLabel) }
