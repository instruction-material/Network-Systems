def normalize_ports(raw_values: list[str]) -> list[int]:
	normalized: list[int] = []
	for raw_value in raw_values:
		# TODO: parse the current entry, reject invalid ports, and append safe values.
		pass
	return normalized


def main() -> None:
	print(normalize_ports(["22", "443", "8080", "bad"]))


if __name__ == "__main__":
	main()
