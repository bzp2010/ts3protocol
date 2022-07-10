package errors

const (
	PacketIncomplete      = "packet incomplete, size: %d but expect %v"
	PacketTypeUnmatched   = "packet type unmatched, type: %d but expect %d"
	PacketLowInitDisorder = "low-level init packet disorder, stage: %d but expect %d"
	InvalidCommand        = "invalid command, reason: %s"
)
