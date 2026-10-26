#!/usr/bin/env python3
"""Count orders per status from an export.

Usage: tools/count_orders.py export.json
"""
import json


class Counter:
    def add(self, row):
        pass


def main(path):
    return json.load(open(path))
