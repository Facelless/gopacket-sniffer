package utils

type Cor struct{}

type colors struct {
	Blue   string
	Red    string
	Yellow string
	Green  string
	Reset  string

	Space    string
	TwoSpace string
}

func (c *Cor) Get() *colors {
	return &colors{
		Blue:     "\033[34m",
		Red:      "\033[31m",
		Yellow:   "\033[33m",
		Green:    "\033[32m",
		Reset:    "\033[0m",
		Space:    "\n",
		TwoSpace: "\n\n",
	}
}
