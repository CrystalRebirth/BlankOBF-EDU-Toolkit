class Counter:
    def __init__(self):
        self.value = 0

    def inc(self):
        self.value += 1
        return self.value

if __name__ == "__main__":
    c = Counter()
    for _ in range(3):
        print(c.inc())
