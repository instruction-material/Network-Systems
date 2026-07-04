#################
#   CONSTANTS   #
#################

MIN_PORT = 1
MAX_PORT = 65535
SAMPLE_PORT_VALUES = ["22", "443", "8080", "bad"]


#################
#   FUNCTIONS   #
#################

def normalize_ports(raw_values: list[str]) -> list[int]:
	"""Convert valid numeric port strings into port numbers"""
	normalized_ports: list[int] = []

	# Check each raw value before converting it into an integer
	for raw_value in raw_values:
		# Skip values that are not decimal port numbers
		if not raw_value.isdigit():
			continue

		port = int(raw_value)

		# Keep only ports inside the valid TCP and UDP range
		if MIN_PORT <= port <= MAX_PORT:
			normalized_ports.append(port)

	return normalized_ports


def main() -> None:
	"""Print the normalized sample ports"""
	print(normalize_ports(SAMPLE_PORT_VALUES))


if __name__ == "__main__":
	main()
