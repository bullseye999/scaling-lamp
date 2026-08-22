#!/usr/bin/env python3
# cvss_calculator.py - Deterministic FIRST.org CVSS v3.1 Base Score Calculator

import math
import re
from typing import Dict, Any, Tuple, Optional

class CVSSv31Calculator:
    """
    Deterministic mathematical implementation of the FIRST.org CVSS v3.1 Specification.
    Guarantees 100% mathematical accuracy without relying on external APIs or LLM math.
    """

    METRIC_WEIGHTS = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {
            'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
            'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}
        },
        'UI': {'N': 0.85, 'R': 0.62},
        'S':  {'U': 'U', 'C': 'C'},
        'C':  {'N': 0.00, 'L': 0.22, 'H': 0.56},
        'I':  {'N': 0.00, 'L': 0.22, 'H': 0.56},
        'A':  {'N': 0.00, 'L': 0.22, 'H': 0.56}
    }

    @staticmethod
    def _roundup(input_val: float) -> float:
        """FIRST.org CVSS v3.1 Roundup specification"""
        int_input = round(input_val * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def calculate_from_metrics(cls, metrics: Dict[str, str]) -> Dict[str, Any]:
        """
        Calculate CVSS v3.1 score given a dictionary of metrics.
        Required keys: AV, AC, PR, UI, S, C, I, A
        """
        req_keys = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        for k in req_keys:
            if k not in metrics:
                raise ValueError(f'Missing required CVSS metric: {k}')

        av = cls.METRIC_WEIGHTS['AV'][metrics['AV']]
        ac = cls.METRIC_WEIGHTS['AC'][metrics['AC']]
        scope = metrics['S']
        pr = cls.METRIC_WEIGHTS['PR'][scope][metrics['PR']]
        ui = cls.METRIC_WEIGHTS['UI'][metrics['UI']]

        conf = cls.METRIC_WEIGHTS['C'][metrics['C']]
        integ = cls.METRIC_WEIGHTS['I'][metrics['I']]
        avail = cls.METRIC_WEIGHTS['A'][metrics['A']]

        # 1. Calculate ISS (Impact Sub-Score)
        iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

        # 2. Calculate Impact
        if scope == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # 4. Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if scope == 'U':
                raw_score = min(impact + exploitability, 10.0)
            else:
                raw_score = min(1.08 * (impact + exploitability), 10.0)
            base_score = cls._roundup(raw_score)

        # 5. Determine Severity Rating
        if base_score == 0.0:
            severity = 'NONE'
        elif base_score <= 3.9:
            severity = 'LOW'
        elif base_score <= 6.9:
            severity = 'MEDIUM'
        elif base_score <= 8.9:
            severity = 'HIGH'
        else:
            severity = 'CRITICAL'

        vector_str = f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"

        return {
            'base_score': base_score,
            'severity': severity,
            'vector_string': vector_str,
            'impact_subscore': round(impact, 2),
            'exploitability_subscore': round(exploitability, 2),
            'metrics': metrics
        }

    @classmethod
    def calculate_from_vector(cls, vector_str: str) -> Dict[str, Any]:
        """
        Parse and calculate CVSS v3.1 from a standard vector string.
        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        clean_vector = vector_str.replace('CVSS:3.1/', '').replace('CVSS:3.0/', '').strip()
        parts = clean_vector.split('/')
        metrics = {}
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                metrics[k.upper()] = v.upper()

        return cls.calculate_from_metrics(metrics)


if __name__ == '__main__':
    # Test with standard known CVE vector: RCE 9.8 Critical
    res = CVSSv31Calculator.calculate_from_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    print('Test 1 (RCE):', res)
    assert res['base_score'] == 9.8
    assert res['severity'] == 'CRITICAL'
