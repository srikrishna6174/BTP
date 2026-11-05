"""
Shared experiment helpers for the EAP-IMP hardware experiment.

Used by iot.py (Raspberry Pi), as_server.py and ap.py (Laptop):
  - Metrics    : per-phase wall / CPU / active time, energy model, bytes
  - summarize  : mean / std / min / median / max over the measured runs
  - write_csvs : per-run CSV + summary CSV

Time columns
  wall_ms   : elapsed time of the phase (includes waiting for the network / peer)
  cpu_ms    : process CPU time. NOTE: on Windows this clock only advances every
              ~15.6 ms, so it is unreliable for phases of a few ms.
  active_ms : wall time minus time blocked in recv(); the compute (+send) time,
              accurate on every OS. Use this for the laptop side.
"""

import csv
import os
import re
import statistics
import time

NON_METRIC = ('run', 'warmup', 'ok')


def slug(name):
    return re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')


def add_common_args(parser, default_runs=50, default_warmup=3):
    parser.add_argument('--runs', type=int,
                        default=int(os.environ.get('RUNS', default_runs)),
                        help='measured runs (default %(default)s)')
    parser.add_argument('--warmup', type=int,
                        default=int(os.environ.get('WARMUP', default_warmup)),
                        help='warm-up runs, logged but excluded from statistics (default %(default)s)')
    parser.add_argument('--out-dir', default=os.environ.get('OUT_DIR', 'results'),
                        help='directory for CSV output (default %(default)s)')
    parser.add_argument('--verbose', action='store_true',
                        help='print every protocol step (automatic for a single run)')
    return parser


class Metrics:
    def __init__(self, power_watts, energy_from_active=False):
        self.power = power_watts
        self.energy_from_active = energy_from_active
        self.reset()

    def reset(self):
        self.phases = []
        self.sent = 0
        self.recv = 0
        self.total = None
        self._tw = self._tc = None
        self._pw = self._pc = None
        self._wait = 0.0
        self._pwait = 0.0
        self._ps = 0
        self._pr = 0
        self._name = None

    # -- timing ---------------------------------------------------------
    def start_total(self):
        self._tw = time.perf_counter()
        self._tc = time.process_time()
        self._wait = 0.0

    def start_phase(self, name):
        self._pw = time.perf_counter()
        self._pc = time.process_time()
        self._pwait = 0.0
        self._ps = 0
        self._pr = 0
        self._name = name

    def add_wait(self, seconds):
        self._wait += seconds
        self._pwait += seconds

    def record_send(self, nbytes):
        self._ps += nbytes
        self.sent += nbytes

    def record_recv(self, nbytes):
        self._pr += nbytes
        self.recv += nbytes

    def _energy_mj(self, cpu_s, active_s):
        busy = active_s if self.energy_from_active else cpu_s
        return busy * self.power * 1000

    def end_phase(self):
        wall = time.perf_counter() - self._pw
        cpu = time.process_time() - self._pc
        active = max(wall - self._pwait, 0.0)
        self.phases.append({
            'name': self._name,
            'wall_ms': wall * 1000,
            'cpu_ms': cpu * 1000,
            'active_ms': active * 1000,
            'energy_mJ': self._energy_mj(cpu, active),
            'sent_B': self._ps,
            'recv_B': self._pr,
        })

    def finish(self):
        wall = time.perf_counter() - self._tw
        cpu = time.process_time() - self._tc
        active = max(wall - self._wait, 0.0)
        self.total = {
            'wall_ms': wall * 1000,
            'cpu_ms': cpu * 1000,
            'active_ms': active * 1000,
            'energy_mJ': self._energy_mj(cpu, active),
            'sent_B': self.sent,
            'recv_B': self.recv,
        }

    # -- output ---------------------------------------------------------
    def as_row(self):
        row = {}
        for p in self.phases:
            key = slug(p['name'])
            for field in ('wall_ms', 'cpu_ms', 'active_ms', 'energy_mJ', 'sent_B', 'recv_B'):
                row[f'{key}_{field}'] = p[field]
        if self.total:
            for field, value in self.total.items():
                row[f'total_{field}'] = value
        return row

    def print_table(self, title):
        """Per-phase table for a single run (the original output format)."""
        t = self.total
        basis = 'active time' if self.energy_from_active else 'CPU time'
        print("\n" + "=" * 86)
        print(f"   {title}")
        print("=" * 86)
        print(f"  Power model: {self.power} W x {basis}")
        print("-" * 86)
        print(f"  {'Phase':<28} {'Wall(ms)':>9} {'CPU(ms)':>9} {'Active(ms)':>10} "
              f"{'Energy(mJ)':>11} {'Sent(B)':>8} {'Recv(B)':>8}")
        print("-" * 86)
        for p in self.phases:
            print(f"  {p['name']:<28} {p['wall_ms']:>9.3f} {p['cpu_ms']:>9.3f} {p['active_ms']:>10.3f} "
                  f"{p['energy_mJ']:>11.4f} {p['sent_B']:>8d} {p['recv_B']:>8d}")
        print("-" * 86)
        print(f"  {'TOTAL':<28} {t['wall_ms']:>9.3f} {t['cpu_ms']:>9.3f} {t['active_ms']:>10.3f} "
              f"{t['energy_mJ']:>11.4f} {t['sent_B']:>8d} {t['recv_B']:>8d}")
        print("=" * 86)
        print(f"  Total Communication : {t['sent_B'] + t['recv_B']} bytes")
        try:
            import resource
            ru = resource.getrusage(resource.RUSAGE_SELF)
            print(f"  Max RSS Memory      : {ru.ru_maxrss} KB")
        except ImportError:
            pass
        print("=" * 86)


# -- statistics ---------------------------------------------------------
def describe(values):
    n = len(values)
    return {
        'n': n,
        'mean': statistics.fmean(values),
        'std': statistics.stdev(values) if n > 1 else 0.0,
        'min': min(values),
        'median': statistics.median(values),
        'max': max(values),
    }


def columns_of(rows):
    cols = []
    for r in rows:
        for k in r:
            if k not in cols and k not in NON_METRIC:
                cols.append(k)
    return cols


def summarize(rows):
    """Stats over measured runs only (not warm-up, completed OK)."""
    good = [r for r in rows if r.get('ok') and not r.get('warmup')]
    out = []
    for col in columns_of(rows):
        vals = [r[col] for r in good if isinstance(r.get(col), (int, float))]
        if vals:
            out.append((col, describe(vals)))
    return len(good), out


def print_summary(title, rows, notes=()):
    measured, stats = summarize(rows)
    warm = sum(1 for r in rows if r.get('warmup'))
    failed = sum(1 for r in rows if not r.get('ok'))
    print("\n" + "=" * 100)
    print(f"   {title}")
    print("=" * 100)
    print(f"  Runs logged: {len(rows)}   warm-up (excluded): {warm}   failed: {failed}   "
          f"measured: {measured}")
    for n in notes:
        print(f"  Note: {n}")
    print("-" * 100)
    print(f"  {'Metric':<40} {'Mean':>11} {'Std':>11} {'Min':>11} {'Median':>11} {'Max':>11}")
    print("-" * 100)
    for col, s in stats:
        print(f"  {col:<40} {s['mean']:>11.4f} {s['std']:>11.4f} {s['min']:>11.4f} "
              f"{s['median']:>11.4f} {s['max']:>11.4f}")
    print("=" * 100)


def write_csvs(out_dir, role, rows):
    """Write <role>_runs_<tag>.csv and <role>_summary_<tag>.csv. Returns both paths."""
    os.makedirs(out_dir, exist_ok=True)
    tag = time.strftime('%Y%m%d_%H%M%S')
    runs_path = os.path.join(out_dir, f'{role}_runs_{tag}.csv')
    summary_path = os.path.join(out_dir, f'{role}_summary_{tag}.csv')

    fields = list(NON_METRIC) + columns_of(rows)
    with open(runs_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, restval='')
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})

    _, stats = summarize(rows)
    with open(summary_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['metric', 'n', 'mean', 'std', 'min', 'median', 'max'])
        for col, s in stats:
            w.writerow([col, s['n']] + [round(s[k], 4) for k in ('mean', 'std', 'min', 'median', 'max')])
    return runs_path, summary_path
