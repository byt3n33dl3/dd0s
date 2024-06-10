all: killer.c
	gcc -Wall -Wvla -Werror -g killer.c -o flood

	@echo "\\dd0s_killer v1.0 (c) 2024 by p3xsouger - Please do not use this program for illegal uses.\\n\\nsyntax: ./flood [[-t IP] [-p PORT] [-r]]\\noptions:\\n	-t the target: IP (default The_Ip_addr)\\n	-p the target: PORT (default 80)\\n	-r set RST flag\\n\\nFlood is a tool involves sending many SYN packets to a specific target.\\n\\nExample: sudo ./flood -t 192.168.0.1 -p 8080"

clean:
	rm killer 
	    @echo Clean done
