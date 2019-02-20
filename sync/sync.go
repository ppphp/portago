package sync

func Sync(method string) {
	switch method {
	case "rsync":
		rsync()
	default:
		rsync()
	}
}
