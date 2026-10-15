package engine

// rateTokens and packetCost share units: packets for pps, bits otherwise.
func (e *Engine) rateTokens() float64 {
	if e.cfg.RatePps > 0 {
		return float64(e.cfg.RatePps)
	}
	return float64(e.cfg.RateBps)
}

func (e *Engine) packetCost(bytes int) float64 {
	if e.cfg.RatePps > 0 {
		return 1
	}
	return float64(bytes * 8)
}
