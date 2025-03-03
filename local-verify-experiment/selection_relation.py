import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import binom

n_values = np.arange(10, 101, 10)
p_values = [0.5, 0.6, 0.7, 0.8, 0.9]  # probabilities of a worker being honest

# P_catch for a given p and n
def compute_p_catch(p, n):
    # min number of honest workers needed to catch collusion
    min_honest_workers = int(np.ceil(n / 2))
    
    # cumulative probability for having at least min_honest_workers honest workers
    P_catch = binom.sf(min_honest_workers - 1, n, p)  # sf is 1 - cdf for at least min_honest_workers
    return P_catch

plt.figure(figsize=(8, 5))
plt.gca().set_facecolor('#f0f0f0')

for p in p_values:
    # P_catch for all specified values of n for this specific p
    P_catch_values = [compute_p_catch(p, n) for n in n_values]
    plt.plot(n_values, P_catch_values, marker='o', label=f'$p = {p}$')

plt.xticks(np.arange(10, 101, 10))
plt.xlabel('$n$')
plt.ylabel('$P_{\\mathrm{catch}}$')
# plt.title('Probability of catching collusion ($P_{\\mathrm{catch}}$) vs. Number of verifiers (n)')
plt.legend(title="Honesty probability (p)")
plt.grid(True, color='white')
plt.show()
