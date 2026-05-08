import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any, TypeVar

from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.models import Config as CredentialConfig
from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util import models as util_models

from conf_helper import ConfHelper
from config import RuleConfig, SecurityGroupConfig

logger = logging.getLogger("AliyunApi")

T = TypeVar("T")

# Constants
DEFAULT_POLICY = "accept"
DEFAULT_DESCRIPTION = "SGM auto managed"
MAX_RETRIES = 3


@dataclass(frozen=True)
class _RuleSpec:
    """Internal specification for a single security group rule action."""

    proto: str
    port: int
    policy: str     # "accept" or "drop"
    cidr_ip: str    # CIDR notation, e.g. "1.2.3.4/32"


class AliyunApiError(Exception):
    """Base exception class for Aliyun API errors."""

class CredentialsError(AliyunApiError):
    """Exception class for credentials errors."""

def _retry(max_retries: int = MAX_RETRIES) -> Callable[[Callable[..., T]], Callable[..., T]]:

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception | None = None
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except AliyunApiError:
                    raise
                except Exception as e:
                    last_exc = e
                    if attempt < max_retries:
                        wait = 2 ** (attempt - 1)
                        logger.warning(
                            "%s failed (attempt %d/%d), retrying in %ds: %s",
                            func.__name__,
                            attempt,
                            max_retries,
                            wait,
                            e,
                        )
                        time.sleep(wait)
            raise AliyunApiError(
                f"{func.__name__} failed after {max_retries} attempts"
            ) from last_exc

        return wrapper

    return decorator


class AliyunApi:
    """Aliyun API client for managing security groups."""

    def __init__(self) -> None:
        self._conf = ConfHelper.get_instance()
        self._clients: dict[str, EcsClient] = {}

    def _get_credentials(self) -> CredentialConfig:
        """Get Aliyun credentials from configuration."""
        ak = self._conf.get("aliyun.ak")
        sk = self._conf.get("aliyun.sk")

        if not ak or not sk:
            raise CredentialsError(
                "阿里云 AK/SK 未配置，请检查 cfg/sgm.yaml 中的 aliyun.ak 和 aliyun.sk"
            )

        return CredentialConfig(
            type="access_key",
            access_key_id=ak,
            access_key_secret=sk,
        )

    def _get_client(self, region_id: str) -> EcsClient:
        """Get or create an ECS client for the specified region (with caching)."""
        if region_id not in self._clients:
            credential = CredentialClient(self._get_credentials())
            config = open_api_models.Config(credential=credential)
            config.region_id = region_id
            self._clients[region_id] = EcsClient(config)
            logger.info("Created ECS client for region %s", region_id)

        return self._clients[region_id]

    @staticmethod
    def _log_api_error(error: Exception) -> None:
        """Log Aliyun API error details."""
        msg = getattr(error, "message", str(error))
        logger.error("API error: %s", msg)
        data = getattr(error, "data", None)
        if data and isinstance(data, dict):
            recommend = data.get("Recommend")
            if recommend:
                logger.error("Recommendation: %s", recommend)

    def describe_security_group_attribute(
        self,
        region_id: str,
        security_group_id: str,
    ) -> dict[str, Any]:
        """Describe security group attributes and rules list, return structured data"""
        client = self._get_client(region_id)
        request = ecs_models.DescribeSecurityGroupAttributeRequest()
        request.region_id = region_id
        request.security_group_id = security_group_id
        runtime = util_models.RuntimeOptions()

        try:
            resp = client.describe_security_group_attribute_with_options(
                request, runtime
            )
            body = resp.body

            result: dict[str, Any] = {
                "security_group_id": getattr(body, "security_group_id", None),
                "security_group_name": getattr(body, "security_group_name", None),
                "region_id": getattr(body, "region_id", None),
                "vpc_id": getattr(body, "vpc_id", None),
                "permissions": [],
            }

            ingress = getattr(body, "permissions", None)
            if ingress:
                for p in getattr(ingress, "permission", []) or []:
                    result["permissions"].append(
                        {
                            "direction": "ingress",
                            "policy": getattr(p, "policy", None),
                            "ip_protocol": getattr(p, "ip_protocol", None),
                            "port_range": getattr(p, "port_range", None),
                            "source_cidr_ip": getattr(p, "source_cidr_ip", None),
                            "dest_cidr_ip": getattr(p, "dest_cidr_ip", None),
                            "description": getattr(p, "description", None),
                            "priority": getattr(p, "priority", None),
                        }
                    )

            egress = getattr(body, "permissions_egress", None)
            if egress:
                for p in getattr(egress, "permission", []) or []:
                    result["permissions"].append(
                        {
                            "direction": "egress",
                            "policy": getattr(p, "policy", None),
                            "ip_protocol": getattr(p, "ip_protocol", None),
                            "port_range": getattr(p, "port_range", None),
                            "source_cidr_ip": getattr(p, "source_cidr_ip", None),
                            "dest_cidr_ip": getattr(p, "dest_cidr_ip", None),
                            "description": getattr(p, "description", None),
                            "priority": getattr(p, "priority", None),
                        }
                    )

            logger.info(
                "Fetched %d rules for SG %s",
                len(result["permissions"]),
                security_group_id,
            )
            return result

        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"DescribeSecurityGroupAttribute failed for {security_group_id}"
            ) from e

    def authorize_security_group(
        self,
        region_id: str,
        security_group_id: str,
        ip_protocol: str,
        port_range: str,
        source_cidr_ip: str,
        policy: str = "accept",
        description: str = "SGM auto managed",
    ) -> None:
        """Authorize security group rule"""
        client = self._get_client(region_id)
        request = ecs_models.AuthorizeSecurityGroupRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy,
            description=description,
        )
        runtime = util_models.RuntimeOptions()

        try:
            client.authorize_security_group_with_options(request, runtime)
            logger.info(
                "Authorized ingress rule: %s:%s from %s to SG %s",
                ip_protocol,
                port_range,
                source_cidr_ip,
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"AuthorizeSecurityGroup failed for SG {security_group_id}"
            ) from e

    def authorize_security_group_egress(
        self,
        region_id: str,
        security_group_id: str,
        ip_protocol: str,
        port_range: str,
        dest_cidr_ip: str,
        policy: str = "accept",
        description: str = "SGM auto managed",
    ) -> None:
        """Authorize security group egress rule"""
        client = self._get_client(region_id)
        request = ecs_models.AuthorizeSecurityGroupEgressRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            dest_cidr_ip=dest_cidr_ip,
            policy=policy,
            description=description,
        )
        runtime = util_models.RuntimeOptions()

        try:
            client.authorize_security_group_egress_with_options(request, runtime)
            logger.info(
                "Authorized egress rule: %s:%s to %s from SG %s",
                ip_protocol,
                port_range,
                dest_cidr_ip,
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"AuthorizeSecurityGroupEgress failed for SG {security_group_id}"
            ) from e

    def revoke_security_group(
        self,
        region_id: str,
        security_group_id: str,
        ip_protocol: str,
        port_range: str,
        source_cidr_ip: str | None = None,
        policy: str | None = None,
        description: str | None = None,
    ) -> None:
        """Revoke security group ingress rule"""
        client = self._get_client(region_id)
        request = ecs_models.RevokeSecurityGroupRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
        )
        if source_cidr_ip is not None:
            request.source_cidr_ip = source_cidr_ip
        if policy is not None:
            request.policy = policy
        if description is not None:
            request.description = description

        runtime = util_models.RuntimeOptions()

        try:
            client.revoke_security_group_with_options(request, runtime)
            logger.info(
                "Revoked ingress rule: %s:%s from SG %s",
                ip_protocol,
                port_range,
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"RevokeSecurityGroup failed for SG {security_group_id}"
            ) from e

    def revoke_security_group_egress(
        self,
        region_id: str,
        security_group_id: str,
        ip_protocol: str,
        port_range: str,
        dest_cidr_ip: str | None = None,
        policy: str | None = None,
        description: str | None = None,
    ) -> None:
        """Revoke security group egress rule"""
        client = self._get_client(region_id)
        request = ecs_models.RevokeSecurityGroupEgressRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
        )
        if dest_cidr_ip is not None:
            request.dest_cidr_ip = dest_cidr_ip
        if policy is not None:
            request.policy = policy
        if description is not None:
            request.description = description

        runtime = util_models.RuntimeOptions()

        try:
            client.revoke_security_group_egress_with_options(request, runtime)
            logger.info(
                "Revoked egress rule: %s:%s from SG %s",
                ip_protocol,
                port_range,
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"RevokeSecurityGroupEgress failed for SG {security_group_id}"
            ) from e


    def _batch_authorize_ingress(
        self,
        region_id: str,
        security_group_id: str,
        specs: list[_RuleSpec],
    ) -> None:
        """Batch add ingress rules in a single API call."""
        if not specs:
            return
        perms = [
            ecs_models.AuthorizeSecurityGroupRequestPermissions(
                ip_protocol=s.proto,
                port_range=f"{s.port}/{s.port}",
                source_cidr_ip=s.cidr_ip,
                policy=s.policy,
                description=DEFAULT_DESCRIPTION,
            )
            for s in specs
        ]
        request = ecs_models.AuthorizeSecurityGroupRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            permissions=perms,
        )
        runtime = util_models.RuntimeOptions()
        try:
            self._get_client(region_id).authorize_security_group_with_options(request, runtime)
            logger.info(
                "Batch authorized %d ingress rule(s) for SG %s",
                len(perms),
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"Batch AuthorizeSecurityGroup failed for SG {security_group_id}"
            ) from e

    def _batch_authorize_egress(
        self,
        region_id: str,
        security_group_id: str,
        specs: list[_RuleSpec],
    ) -> None:
        """Batch add egress rules in a single API call."""
        if not specs:
            return
        perms = [
            ecs_models.AuthorizeSecurityGroupEgressRequestPermissions(
                ip_protocol=s.proto,
                port_range=f"{s.port}/{s.port}",
                dest_cidr_ip=s.cidr_ip,
                policy=s.policy,
                description=DEFAULT_DESCRIPTION,
            )
            for s in specs
        ]
        request = ecs_models.AuthorizeSecurityGroupEgressRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            permissions=perms,
        )
        runtime = util_models.RuntimeOptions()
        try:
            self._get_client(region_id).authorize_security_group_egress_with_options(request, runtime)
            logger.info(
                "Batch authorized %d egress rule(s) for SG %s",
                len(perms),
                security_group_id,
            )
        except Exception as e:
            self._log_api_error(e)
            raise AliyunApiError(
                f"Batch AuthorizeSecurityGroupEgress failed for SG {security_group_id}"
            ) from e

    def _batch_revoke_ingress(
        self,
        region_id: str,
        security_group_id: str,
        specs: list[_RuleSpec],
    ) -> None:
        """Batch remove ingress rules in a single API call; tolerates missing rules."""
        if not specs:
            return
        perms = [
            ecs_models.RevokeSecurityGroupRequestPermissions(
                ip_protocol=s.proto,
                port_range=f"{s.port}/{s.port}",
                source_cidr_ip=s.cidr_ip,
                policy=s.policy,
                description=DEFAULT_DESCRIPTION,
            )
            for s in specs
        ]
        request = ecs_models.RevokeSecurityGroupRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            permissions=perms,
        )
        runtime = util_models.RuntimeOptions()
        try:
            self._get_client(region_id).revoke_security_group_with_options(request, runtime)
            logger.info(
                "Batch revoked %d ingress rule(s) for SG %s",
                len(perms),
                security_group_id,
            )
        except AliyunApiError:
            raise
        except Exception as e:
            # Old rules may not exist; log and continue
            logger.warning(
                "Batch revoke ingress for SG %s may have partial failure: %s",
                security_group_id,
                e,
            )

    def _batch_revoke_egress(
        self,
        region_id: str,
        security_group_id: str,
        specs: list[_RuleSpec],
    ) -> None:
        """Batch remove egress rules in a single API call; tolerates missing rules."""
        if not specs:
            return
        perms = [
            ecs_models.RevokeSecurityGroupEgressRequestPermissions(
                ip_protocol=s.proto,
                port_range=f"{s.port}/{s.port}",
                dest_cidr_ip=s.cidr_ip,
                policy=s.policy,
                description=DEFAULT_DESCRIPTION,
            )
            for s in specs
        ]
        request = ecs_models.RevokeSecurityGroupEgressRequest(
            region_id=region_id,
            security_group_id=security_group_id,
            permissions=perms,
        )
        runtime = util_models.RuntimeOptions()
        try:
            self._get_client(region_id).revoke_security_group_egress_with_options(request, runtime)
            logger.info(
                "Batch revoked %d egress rule(s) for SG %s",
                len(perms),
                security_group_id,
            )
        except AliyunApiError:
            raise
        except Exception as e:
            logger.warning(
                "Batch revoke egress for SG %s may have partial failure: %s",
                security_group_id,
                e,
            )

    @staticmethod
    def _collect_sg_rules(
        sg: SecurityGroupConfig,
        old_ip: str | None,
        new_ip: str,
    ) -> tuple[
        list[_RuleSpec],  # ingress to revoke
        list[_RuleSpec],  # egress to revoke
        list[_RuleSpec],  # ingress to authorize
        list[_RuleSpec],  # egress to authorize
    ]:
        """
        Derive all rule specs for a security group.

        Expands ingress/egress/all into flat ingress and egress lists,
        and maps allow -> policy="accept", drop -> policy="drop".
        Returns four lists: (ingress_revoke, egress_revoke, ingress_auth, egress_auth).
        """
        # Expand allow + drop for each effective direction
        ingress_pairs: list[tuple[RuleConfig, str]] = [
            (r, "accept") for r in sg.ingress.allow + sg.all.allow
        ] + [
            (r, "drop") for r in sg.ingress.drop + sg.all.drop
        ]
        egress_pairs: list[tuple[RuleConfig, str]] = [
            (r, "accept") for r in sg.egress.allow + sg.all.allow
        ] + [
            (r, "drop") for r in sg.egress.drop + sg.all.drop
        ]

        ingress_revoke: list[_RuleSpec] = []
        egress_revoke: list[_RuleSpec] = []

        if old_ip:
            ingress_revoke = [
                _RuleSpec(proto=r.proto, port=r.port, policy=p, cidr_ip=f"{old_ip}/32")
                for r, p in ingress_pairs
            ]
            egress_revoke = [
                _RuleSpec(proto=r.proto, port=r.port, policy=p, cidr_ip=f"{old_ip}/32")
                for r, p in egress_pairs
            ]

        ingress_auth = [
            _RuleSpec(proto=r.proto, port=r.port, policy=p, cidr_ip=f"{new_ip}/32")
            for r, p in ingress_pairs
        ]
        egress_auth = [
            _RuleSpec(proto=r.proto, port=r.port, policy=p, cidr_ip=f"{new_ip}/32")
            for r, p in egress_pairs
        ]

        return ingress_revoke, egress_revoke, ingress_auth, egress_auth

    def _cleanup_stale_rules(
        self,
        region_id: str,
        security_group_id: str,
        expected_ingress: list[_RuleSpec],
        expected_egress: list[_RuleSpec],
    ) -> None:
        """
        Remove SGM-managed rules that no longer appear in the current configuration.

        Queries the live security group, filters rules whose description equals
        DEFAULT_DESCRIPTION, then batch-revokes any that are absent from the
        expected ingress/egress sets derived from the current config.
        """
        try:
            sg_info = self.describe_security_group_attribute(region_id, security_group_id)
        except AliyunApiError:
            logger.warning(
                "Could not describe SG %s, skipping stale rule cleanup",
                security_group_id,
            )
            return

        # Build normalised lookup sets from the expected specs
        expected_ingress_keys: set[tuple[str, str, str, str]] = {
            (s.proto.lower(), f"{s.port}/{s.port}", s.cidr_ip, s.policy.lower())
            for s in expected_ingress
        }
        expected_egress_keys: set[tuple[str, str, str, str]] = {
            (s.proto.lower(), f"{s.port}/{s.port}", s.cidr_ip, s.policy.lower())
            for s in expected_egress
        }

        stale_ingress: list[dict[str, Any]] = []
        stale_egress: list[dict[str, Any]] = []

        for perm in sg_info.get("permissions", []):
            if perm.get("description") != DEFAULT_DESCRIPTION:
                continue
            direction = perm.get("direction")
            proto = (perm.get("ip_protocol") or "").lower()
            port_range = perm.get("port_range") or ""
            policy = (perm.get("policy") or "").lower()

            if direction == "ingress":
                cidr = perm.get("source_cidr_ip") or ""
                if cidr == "":
                    logger.warning("Ingress rule with empty cidr_ip: %s", perm)
                    continue
                if (proto, port_range, cidr, policy) not in expected_ingress_keys:
                    stale_ingress.append(perm)
            elif direction == "egress":
                cidr = perm.get("dest_cidr_ip") or ""
                if cidr == "":
                    logger.warning("Egress rule with empty dest_cidr_ip: %s", perm)
                    continue
                if (proto, port_range, cidr, policy) not in expected_egress_keys:
                    stale_egress.append(perm)

        if not stale_ingress and not stale_egress:
            logger.debug("No stale SGM rules found in SG %s", security_group_id)
            return

        logger.info(
            "Cleaning up stale SGM rules in SG %s: ingress=%d egress=%d",
            security_group_id,
            len(stale_ingress),
            len(stale_egress),
        )

        if stale_ingress:
            ingress_perms = [
                ecs_models.RevokeSecurityGroupRequestPermissions(
                    ip_protocol=p.get("ip_protocol"),
                    port_range=p.get("port_range"),
                    source_cidr_ip=p.get("source_cidr_ip"),
                    policy=p.get("policy"),
                    description=DEFAULT_DESCRIPTION,
                )
                for p in stale_ingress
            ]

            req = ecs_models.RevokeSecurityGroupRequest(
                region_id=region_id,
                security_group_id=security_group_id,
                permissions=ingress_perms,
            )
            runtime = util_models.RuntimeOptions()
            try:
                self._get_client(region_id).revoke_security_group_with_options(req, runtime)
                logger.info(
                    "Removed %d stale ingress rule(s) from SG %s",
                    len(ingress_perms),
                    security_group_id,
                )
            except Exception as e:
                logger.warning(
                    "Failed to remove stale ingress rules in SG %s: %s",
                    security_group_id,
                    e,
                )

        if stale_egress:
            egress_perms = [
                ecs_models.RevokeSecurityGroupEgressRequestPermissions(
                    ip_protocol=p.get("ip_protocol"),
                    port_range=p.get("port_range"),
                    dest_cidr_ip=p.get("dest_cidr_ip"),
                    policy=p.get("policy"),
                    description=DEFAULT_DESCRIPTION,
                )
                for p in stale_egress
            ]
            req = ecs_models.RevokeSecurityGroupEgressRequest(
                region_id=region_id,
                security_group_id=security_group_id,
                permissions=egress_perms,
            )
            runtime = util_models.RuntimeOptions()
            try:
                self._get_client(region_id).revoke_security_group_egress_with_options(req, runtime)
                logger.info(
                    "Removed %d stale egress rule(s) from SG %s",
                    len(egress_perms),
                    security_group_id,
                )
            except Exception as e:
                logger.warning(
                    "Failed to remove stale egress rules in SG %s: %s",
                    security_group_id,
                    e,
                )

    def sync_security_groups(self, old_ip: str | None, new_ip: str) -> None:
        """
        Batch-sync all configured security groups for an IP change.

        For each security group the flow is:
          1. Collect all rule specs (allow + drop, ingress + egress + all expanded).
          2. Batch-revoke old-IP rules (single API call per direction).
          3. Batch-authorize new-IP rules (single API call per direction).
          4. Clean up any surviving SGM-managed rules absent from current config.
        """
        sg_configs: list[SecurityGroupConfig] = self._conf.model.securityGroup

        if not sg_configs:
            logger.warning("No security group configured in cfg/sgm.yaml")
            return

        for sg in sg_configs:
            logger.info("Syncing security group %s in %s", sg.id, sg.region)

            ingress_revoke, egress_revoke, ingress_auth, egress_auth = (
                self._collect_sg_rules(sg, old_ip, new_ip)
            )

            # Step 1: revoke old-IP rules
            if ingress_revoke:
                self._batch_revoke_ingress(sg.region, sg.id, ingress_revoke)
            if egress_revoke:
                self._batch_revoke_egress(sg.region, sg.id, egress_revoke)

            # Step 2: authorize new-IP rules
            if ingress_auth:
                self._batch_authorize_ingress(sg.region, sg.id, ingress_auth)
            if egress_auth:
                self._batch_authorize_egress(sg.region, sg.id, egress_auth)

            # Step 3: remove any surviving SGM rules not in current config
            self._cleanup_stale_rules(sg.region, sg.id, ingress_auth, egress_auth)

            logger.info(
                "SG %s synced: revoked ingress=%d egress=%d, authorized ingress=%d egress=%d",
                sg.id,
                len(ingress_revoke),
                len(egress_revoke),
                len(ingress_auth),
                len(egress_auth),
            )

        logger.info("All security groups synced successfully")
