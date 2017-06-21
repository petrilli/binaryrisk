# -*- coding: utf-8 -*-
import csv
import pytest

from main import (
    matrix_threat_scope,
    matrix_protection_capability,
    matrix_attack_effectiveness,
    matrix_occurrence,
    matrix_threat_likelihood,
    matrix_harm,
    matrix_valuation,
    matrix_impact,
    matrix_risk,
)


def test_truth():
    assert True


@pytest.fixture
def bra_permutations():
    """Loads the permutations and builds out a dictionary that can be used
    to get all the answers, including intermediate steps."""

    def string_to_bool(s):
        return True if s == "TRUE" else False

    permutations = []

    with open("permutations.tsv", "r") as tsvfile:
        reader = csv.DictReader(tsvfile, dialect="excel-tab")
        for row in reader:
            permutations.append({
                # Questions
                'skills_required':
                    string_to_bool(row["Is skill required?"]),
                'resources_required':
                    string_to_bool(row[
                                       "Does the attack require significant resources?"]),
                'failure_rate':
                    string_to_bool(row["Can the defenses fail?"]),
                'coverage':
                    string_to_bool(row[
                                       "Does the defense cover all access points to the asset?"]),
                'vulnerability_accessible':
                    string_to_bool(row["Are there any pre-conditions to the attack?"]),
                'preconditions':
                    string_to_bool(row["Is the vulnerability always present?"]),
                'asset_cost':
                    string_to_bool(row["Significant repair cost?"]),
                'asset_value':
                    string_to_bool(row["Significant business value?"]),
                'internal':
                    string_to_bool(row["Consequences from internal sources?"]),
                'external':
                    string_to_bool(row["Consequences from external sources?"]),

                # Intermediate matrix calculations
                'matrix_threat_scope': row["Threat"],
                'matrix_protection_capability': row["Protection"],
                'matrix_attack_effectiveness': row["Effectiveness"],
                'matrix_occurrence': row["Occurrence"],
                'matrix_threat_likelihood': row["Likelihood"],
                'matrix_harm': row["Harm"],
                'matrix_valuation': row["Valuation"],
                'matrix_impact': row["Impact"],
                'matrix_likelihood': row["Likelihood"],
                'matrix_risk': row["Risk"],
            })
        return permutations


def test_matrix_threat_scope(bra_permutations):
    for p in bra_permutations:
        assert matrix_threat_scope(
            p["skills_required"], p["resources_required"]
        ) == p["matrix_threat_scope"]


def test_matrix_protection_capability(bra_permutations):
    for p in bra_permutations:
        assert matrix_protection_capability(
            p["failure_rate"], p["coverage"]
        ) == p["matrix_protection_capability"]


def test_matrix_attack_effectiveness(bra_permutations):
    for p in bra_permutations:
        assert matrix_attack_effectiveness(
            p["matrix_threat_scope"],
            p["matrix_protection_capability"]
        ) == p["matrix_attack_effectiveness"]


def test_matrix_occurrence(bra_permutations):
    for p in bra_permutations:
        assert matrix_occurrence(
            p["vulnerability_accessible"], p["preconditions"]
        ) == p["matrix_occurrence"]


def test_matrix_threat_likelihood(bra_permutations):
    for p in bra_permutations:
        assert matrix_threat_likelihood(
            p["matrix_attack_effectiveness"],
            p["matrix_occurrence"]
        ) == p["matrix_threat_likelihood"]


def test_matrix_harm(bra_permutations):
    for p in bra_permutations:
        assert matrix_harm(
            p["internal"], p["external"]
        ) == p["matrix_harm"]


def test_matrix_valuation(bra_permutations):
    for p in bra_permutations:
        assert matrix_valuation(
            p["asset_value"], p["asset_cost"]
        ) == p["matrix_valuation"]


def test_matrix_impact(bra_permutations):
    for p in bra_permutations:
        assert matrix_impact(
            p["matrix_harm"], p["matrix_valuation"]
        ) == p["matrix_impact"]


def test_matrix_risk(bra_permutations):
    for p in bra_permutations:
        assert matrix_risk(
            p["matrix_impact"], p["matrix_likelihood"]
        ) == p["matrix_risk"]
