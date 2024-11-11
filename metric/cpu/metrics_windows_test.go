package cpu

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent-system-metrics/metric/helpers/pdh"
)

func TestXX(t *testing.T) {
	h, err := pdh.PdhOpenQuery("", 0)
	fmt.Println(err)
	c, _ := pdh.PdhAddEnglishCounter(h, "", 0)
	fmt.Println(pdh.PdhGetCounterInfo(c))
}
