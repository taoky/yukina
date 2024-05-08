# Quick and dirty script to process the output of the cache hit rate
# (output from `rg -z -F "Hit rate"` in output log directory)

import re
import matplotlib.pyplot as plt
from datetime import datetime

FORMAT = re.compile(r"\d+:(.+)  INFO.+, Hit rate: (\d+.\d+)%")

x = []
y = []

with open("out") as f:
    for line in f:
        m = FORMAT.match(line.strip())
        if m:
            print(m.groups())
            x.append(datetime.fromisoformat(m.group(1)))
            y.append(float(m.group(2)))

combined = sorted(zip(x, y), key=lambda x: x[0])
x, y = zip(*combined)

plt.figure(figsize=(10, 5))
plt.plot(x, y, marker='o')
plt.xlabel('Time')
plt.ylabel('Percentage')
plt.xticks(rotation=45)

# Change following line
plt.title('Yukina Hit Rate Over Time (nix-channels, tag 20240409)')

plt.tight_layout()
plt.savefig('tmp.png')
plt.show()
