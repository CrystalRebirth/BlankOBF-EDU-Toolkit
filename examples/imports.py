import math
from datetime import datetime

def area(r: float) -> float:
    return math.pi * r * r

if __name__ == "__main__":
    print("area:", area(3.0))
    print("time:", datetime.utcnow().isoformat())
