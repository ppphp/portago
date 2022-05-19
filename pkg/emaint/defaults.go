package emaint

var (
	CHECK = map[string]string{"short": "-c", "long": "--check",
		"help":   "Check for problems (a default option for most modules)",
		"status": "Checking %s for problems",
		"action": "store_true",
		"func":   "check",
	}

	FIX = map[string]string{"short": "-f", "long": "--fix",
		"help":   "Attempt to fix problems (a default option for most modules)",
		"status": "Attempting to fix %s",
		"action": "store_true",
		"func":   "fix",
	}

	VERSION = map[string]string{"long": "--version",
		"help":   "show program's version number and exit",
		"action": "store_true",
	}

	DEFAULT_OPTIONS = map[string]map[string]string{"check": CHECK, "fix": FIX, "version": VERSION}
)
