def normalize_ports(raw_values: list[str]) -> list[int]:
	normalized: list[int] = []
	for raw_value in raw_values:
		if not raw_value.isdigit():
			continue
		port = int(raw_value)
		if 1 <= port <= 65535:
			normalized.append(port)
	return normalized


def main() -> None:
	print(normalize_ports(["22", "443", "8080", "bad"]))


if __name__ == "__main__":
	main()
