import os
from flask import Flask, redirect, render_template, url_for
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import BooleanField, StringField
from wtforms.widgets import TextArea
from google.appengine.ext import ndb

from models import AssessmentResponses, Assessment


app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)


class BinaryRiskForm(FlaskForm):
    reference = StringField(
        u"Reference ID",
        description=u"For example, a Jira ticket.",
        render_kw={'class': 'form-control'}
    )
    skills_required = BooleanField(
        u"Are unique skills required to execute the attack successfully?",
    )
    resources_required = BooleanField(
        u"Are significant resources required to execute the attack successfully?",
    )
    failure_rate = BooleanField(
        u"Is it possible that defenses fail to protect against the attack?",
    )
    coverage = BooleanField(
        u"Do the defenses cover all access methods to the asset?",
    )
    vulnerability_accessible = BooleanField(
        u"Is the vulnerability always present in the asset?",
    )
    preconditions = BooleanField(
        u"Are there significant prerequisites to completing the attack successfully?",
    )
    asset_cost = BooleanField(
        u"Is there a significant cost to repair or replace this asset?",
    )
    asset_value = BooleanField(
        u"Does the asset have significant value to the company?",
    )
    internal = BooleanField(
        u"Will there be consequences to an internal attack?",
    )
    external = BooleanField(
        u"Will there be consequences to an external attack?",
    )
    comment = StringField(
        u"Additional Information",
        widget=TextArea(),
        render_kw={'class': 'form-control'}
    )

    def risk_score(self):
        likelihood = matrix_threat_likelihood(
            matrix_attack_effectiveness(
                matrix_threat_scope(
                    self.resources_required.data,
                    self.skills_required.data
                ),
                matrix_protection_capability(
                    self.coverage.data,
                    self.failure_rate.data
                )
            ),
            matrix_occurrence(
                self.vulnerability_accessible.data,
                self.preconditions.data
            )
        )
        impact = matrix_impact(
            matrix_harm(
                self.internal.data,
                self.external.data
            ),
            matrix_valuation(
                self.asset_cost.data,
                self.asset_value.data
            )
        )
        risk = matrix_risk(impact, likelihood)

        return likelihood, impact, risk


# Step 1: Determine likelihood
def matrix_threat_scope(skills_required, resources_required):
    return {
        (True, True): 'S',
        (True, False): 'M',
        (False, True): 'M',
        (False, False): 'L',
    }[(skills_required, resources_required)]


def matrix_protection_capability(failure_rate, coverage):
    return {
        (True, True): 'P',
        (True, False): 'I',
        (False, True): 'C',
        (False, False): 'P',
    }[(failure_rate, coverage)]


def matrix_attack_effectiveness(threat_scope, protection_capability):
    return {
        ('S', 'C'): 'L',
        ('S', 'P'): 'L',
        ('S', 'I'): 'O',
        ('M', 'C'): 'L',
        ('M', 'P'): 'O',
        ('M', 'I'): 'C',
        ('L', 'C'): 'O',
        ('L', 'P'): 'C',
        ('L', 'I'): 'C',
    }[(threat_scope, protection_capability)]


def matrix_occurrence(vulnerability_accessible, preconditions):
    return {
        (True, True): 'P',
        (True, False): 'R',
        (False, True): 'A',
        (False, False): 'P',
    }[(vulnerability_accessible, preconditions)]


def matrix_threat_likelihood(attack_effectiveness, ocurrence):
    return {
        ('L', 'R'): 'L',
        ('L', 'P'): 'L',
        ('L', 'A'): 'M',
        ('O', 'R'): 'L',
        ('O', 'P'): 'M',
        ('O', 'A'): 'H',
        ('C', 'R'): 'M',
        ('C', 'P'): 'H',
        ('C', 'A'): 'H',
    }[(attack_effectiveness, ocurrence)]


# Step 2: Determine impact
def matrix_harm(internal, external):
    return {
        (True, True): 'D',
        (True, False): 'M',
        (False, True): 'M',
        (False, False): 'L',
    }[(internal, external)]


def matrix_valuation(asset_value, asset_cost):
    return {
        (True, True): 'E',
        (True, False): 'S',
        (False, True): 'S',
        (False, False): 'P',
    }[(asset_value, asset_cost)]


def matrix_impact(harm, valuation):
    return {
        ('L', 'E'): 'M',
        ('L', 'S'): 'L',
        ('L', 'P'): 'L',
        ('M', 'E'): 'H',
        ('M', 'S'): 'M',
        ('M', 'P'): 'L',
        ('D', 'E'): 'H',
        ('D', 'S'): 'H',
        ('D', 'P'): 'M',
    }[(harm, valuation)]


# Step 3: Determine risk
def matrix_risk(impact, likelihood):
    return {
        ('L', 'H'): 'M',
        ('L', 'M'): 'L',
        ('L', 'L'): 'L',
        ('M', 'H'): 'H',
        ('M', 'M'): 'M',
        ('M', 'L'): 'L',
        ('H', 'H'): 'H',
        ('H', 'M'): 'H',
        ('H', 'L'): 'M',
    }[(impact, likelihood)]


@app.route('/', methods=['GET', 'POST'])
def binary_risk_form():
    form = BinaryRiskForm()
    if form.validate_on_submit():
        likelihood, impact, risk = form.risk_score()

        assessment = Assessment(
            version="2017-05-20",

            reference=form.reference.data,
            comment=form.comment.data,

            likelihood=likelihood,
            impact=impact,
            risk=risk,

            answers=AssessmentResponses(
                skills_required=form.skills_required.data,
                resources_required=form.resources_required.data,
                failure_rate=form.failure_rate.data,
                coverage=form.coverage.data,
                vulnerability_accessible=form.vulnerability_accessible.data,
                preconditions=form.preconditions.data,
                asset_cost=form.asset_cost.data,
                asset_value=form.asset_value.data,
                internal=form.internal.data,
                external=form.external.data,
            )
        )
        assessment_key = assessment.put()

        return redirect(
            url_for('binary_risk_assessment', key=assessment_key.id())
        )
    return render_template('main.html', form=form)


@app.route('/<int:key>', methods=['GET'])
def binary_risk_assessment(key):
    assessment_key = ndb.Key(Assessment, key)
    assessment = assessment_key.get()

    return render_template('assessment.html',
                           reference=assessment.reference,
                           likelihood=assessment.likelihood,
                           impact=assessment.impact,
                           risk=assessment.risk,
                           comment=assessment.comment)


@app.route('/reference/<string:reference>', methods=['GET'])
def lookup_reference(reference):
    assessments = Assessment.query(
        Assessment.reference == reference
    ).order(
        -Assessment.created_at
    ).fetch()
    return render_template("references.html",
                           reference=reference,
                           assessments=assessments)


if __name__ == '__main__':
    app.run(debug=True)
