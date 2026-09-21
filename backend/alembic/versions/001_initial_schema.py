"""
CloudShield IQ — Initial Database Schema Migration
Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-09-07
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. security_events table
    op.create_table(
        'security_events',
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('cloud_provider', sa.String(length=32), nullable=False),
        sa.Column('event_source', sa.String(length=128), nullable=False, server_default='audit_logs'),
        sa.Column('resource_type', sa.String(length=128), nullable=False),
        sa.Column('resource_id', sa.String(length=512), nullable=True),
        sa.Column('raw_action', sa.String(length=256), nullable=False),
        sa.Column('canonical_action', sa.String(length=64), nullable=False),
        sa.Column('actor_type', sa.String(length=32), nullable=False),
        sa.Column('actor_name', sa.String(length=256), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('region', sa.String(length=64), nullable=True, server_default='global'),
        sa.Column('mfa_used', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('outcome', sa.String(length=32), nullable=False, server_default='Success'),
        sa.Column('session_duration_s', sa.Integer(), nullable=True),
        sa.Column('has_session', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('metadata_payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index('ix_security_events_event_id', 'security_events', ['event_id'], unique=False)
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'], unique=False)
    op.create_index('ix_security_events_cloud_provider', 'security_events', ['cloud_provider'], unique=False)
    op.create_index('ix_security_events_resource_type', 'security_events', ['resource_type'], unique=False)
    op.create_index('ix_security_events_resource_id', 'security_events', ['resource_id'], unique=False)
    op.create_index('ix_security_events_canonical_action', 'security_events', ['canonical_action'], unique=False)
    op.create_index('ix_security_events_actor_type', 'security_events', ['actor_type'], unique=False)
    op.create_index('ix_security_events_actor_name', 'security_events', ['actor_name'], unique=False)
    op.create_index('ix_events_provider_timestamp', 'security_events', ['cloud_provider', 'timestamp'], unique=False)
    op.create_index('ix_events_provider_resource', 'security_events', ['cloud_provider', 'resource_type'], unique=False)
    op.create_index('ix_events_actor_canonical', 'security_events', ['actor_type', 'canonical_action'], unique=False)

    # 2. risk_assessments table
    op.create_table(
        'risk_assessments',
        sa.Column('assessment_id', sa.String(length=64), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=True),
        sa.Column('resource_id', sa.String(length=512), nullable=True),
        sa.Column('cloud_provider', sa.String(length=32), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('anomaly_score', sa.Float(), nullable=False),
        sa.Column('is_anomaly', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('shap_values', sa.JSON(), nullable=False),
        sa.Column('top_feature', sa.String(length=128), nullable=True),
        sa.Column('top_feature_impact', sa.Float(), nullable=True),
        sa.Column('model_version', sa.String(length=32), nullable=False, server_default='v0.1.0'),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('assessment_id')
    )
    op.create_index('ix_risk_assessments_assessment_id', 'risk_assessments', ['assessment_id'], unique=False)
    op.create_index('ix_risk_assessments_event_id', 'risk_assessments', ['event_id'], unique=False)
    op.create_index('ix_risk_assessments_resource_id', 'risk_assessments', ['resource_id'], unique=False)
    op.create_index('ix_risk_assessments_cloud_provider', 'risk_assessments', ['cloud_provider'], unique=False)
    op.create_index('ix_risk_assessments_severity', 'risk_assessments', ['severity'], unique=False)
    op.create_index('ix_assessments_provider_severity', 'risk_assessments', ['cloud_provider', 'severity'], unique=False)
    op.create_index('ix_assessments_evaluated_at', 'risk_assessments', ['evaluated_at'], unique=False)

    # 3. security_findings table
    op.create_table(
        'security_findings',
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('cloud_provider', sa.String(length=32), nullable=False),
        sa.Column('resource_id', sa.String(length=512), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('shap_top_feature', sa.String(length=128), nullable=True),
        sa.Column('shap_impact', sa.Float(), nullable=True),
        sa.Column('compliance_violations', sa.JSON(), nullable=False),
        sa.Column('remediation_guidance', sa.Text(), nullable=False),
        sa.Column('cli_remediation_command', sa.Text(), nullable=True),
        sa.Column('terraform_remediation_snippet', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('finding_id')
    )
    op.create_index('ix_security_findings_finding_id', 'security_findings', ['finding_id'], unique=False)
    op.create_index('ix_security_findings_cloud_provider', 'security_findings', ['cloud_provider'], unique=False)
    op.create_index('ix_security_findings_resource_id', 'security_findings', ['resource_id'], unique=False)
    op.create_index('ix_security_findings_category', 'security_findings', ['category'], unique=False)
    op.create_index('ix_security_findings_severity', 'security_findings', ['severity'], unique=False)
    op.create_index('ix_security_findings_status', 'security_findings', ['status'], unique=False)

    # 4. compliance_results table
    op.create_table(
        'compliance_results',
        sa.Column('result_id', sa.String(length=64), nullable=False),
        sa.Column('control_id', sa.String(length=64), nullable=False),
        sa.Column('control_name', sa.String(length=256), nullable=False),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('cloud_provider', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('evaluated_resources', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_resources', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_resource_ids', sa.JSON(), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('result_id')
    )
    op.create_index('ix_compliance_results_result_id', 'compliance_results', ['result_id'], unique=False)
    op.create_index('ix_compliance_results_control_id', 'compliance_results', ['control_id'], unique=False)
    op.create_index('ix_compliance_results_framework', 'compliance_results', ['framework'], unique=False)
    op.create_index('ix_compliance_results_cloud_provider', 'compliance_results', ['cloud_provider'], unique=False)
    op.create_index('ix_compliance_results_status', 'compliance_results', ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('compliance_results')
    op.drop_table('security_findings')
    op.drop_table('risk_assessments')
    op.drop_table('security_events')
