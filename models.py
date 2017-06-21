from google.appengine.ext import ndb


class AssessmentResponses(ndb.Model):
    """Represents all the answers to a binary risk assessment."""
    skills_required = ndb.BooleanProperty(required=True)
    resources_required = ndb.BooleanProperty(required=True)
    failure_rate = ndb.BooleanProperty(required=True)
    coverage = ndb.BooleanProperty(required=True)
    vulnerability_accessible = ndb.BooleanProperty(required=True)
    preconditions = ndb.BooleanProperty(required=True)
    asset_cost = ndb.BooleanProperty(required=True)
    asset_value = ndb.BooleanProperty(required=True)
    internal = ndb.BooleanProperty(required=True)
    external = ndb.BooleanProperty(required=True)


class Assessment(ndb.Model):
    # Information provided by the requester
    reference = ndb.StringProperty(indexed=True)
    answers = ndb.StructuredProperty(AssessmentResponses)
    comment = ndb.TextProperty()

    # Calculated information
    likelihood = ndb.StringProperty(required=True, choices=('L', 'M', 'H'))
    impact = ndb.StringProperty(required=True, choices=('L', 'M', 'H'))
    risk = ndb.StringProperty(required=True, choices=('L', 'M', 'H'))

    # Metadata
    version = ndb.StringProperty(required=True, indexed=True)
    created_at = ndb.DateTimeProperty(auto_now_add=True)
    created_by = ndb.UserProperty(auto_current_user_add=True)
