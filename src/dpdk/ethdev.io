; Define pipeline input ports
port in 0 ethdev net_tap0 rxq 0 bsz 1
port in 1 ethdev net_tap1 rxq 0 bsz 1
port in 2 ethdev net_tap2 rxq 0 bsz 1

; Define pipeline output ports
port out 0 ethdev net_tap0 txq 0 bsz 1
port out 1 ethdev net_tap1 txq 0 bsz 1
port out 2 ethdev net_tap2 txq 0 bsz 1


