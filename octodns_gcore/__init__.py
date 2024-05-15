#
#
#

import http
import logging
import urllib.parse
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import GeoCodes, Record, Update

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.4'


class GCoreClientException(ProviderException):
    def __init__(self, r):
        super().__init__(r.text)


class GCoreClientBadRequest(GCoreClientException):
    def __init__(self, r):
        super().__init__(r)


class GCoreClientNotFound(GCoreClientException):
    def __init__(self, r):
        super().__init__(r)


class _GcoreDynamicRecord(Record):
    def __init__(self, zone, name, data, source=None, context=None):
        super().__init__(zone, name, data, source, context)

    @property
    def healthcheck_host(self):
        """Gcore API field : meta['failover']['host']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) != 'HTTP':
            return None
        try:
            return healthcheck['host']
        except KeyError:
            return 'gcore-healthcheck.tld'

    @property
    def healthcheck_path(self):
        """Gcore API field : meta['failover']['url']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) != 'HTTP':
            return None
        try:
            return healthcheck['path']
        except KeyError:
            return '/dns-monitor'

    @property
    def healthcheck_protocol(self):
        try:
            return self.octodns['healthcheck']['protocol']
        except KeyError:
            return 'HTTP'

    @property
    def healthcheck_port(self):
        try:
            return int(self.octodns['healthcheck']['port'])
        except KeyError:
            return 80

    @property
    def healthcheck_frequency(self):
        """Gcore API field : meta['failover']['frequency']"""
        try:
            return self.octodns['healthcheck']['frequency']
        except KeyError:
            return '60'

    @property
    def healthcheck_http_status_code(self):
        """Gcore API field : meta['failover']['http_status_code']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) != 'HTTP':
            return None
        try:
            return self.octodns['healthcheck']['http_status_code']
        except KeyError:
            return '200'

    @property
    def healthcheck_method(self):
        """Gcore API field : meta['failover']['method']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) != 'HTTP':
            return None
        try:
            return self.octodns['healthcheck']['method']
        except KeyError:
            return 'GET'

    @property
    def healthcheck_regexp(self):
        """Gcore API field : meta['failover']['regexp']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) == 'ICMP':
            return None
        try:
            return self.octodns['healthcheck']['regexp']
        except KeyError:
            return 'ok'

    @property
    def healthcheck_command(self):
        """Gcore API field : meta['failover']['command']"""
        healthcheck = self.octodns.get('healthcheck', {})
        protocol = healthcheck.get('protocol', None)
        if protocol != "TCP" and protocol != "UDP":
            return None
        try:
            return self.octodns['healthcheck']['command']
        except KeyError:
            return 'GET / HTTP/1.1\n\n'

    @property
    def healthcheck_tls(self):
        """Gcore API field : meta['failover']['tls']"""
        healthcheck = self.octodns.get('healthcheck', {})
        if healthcheck.get('protocol', None) != 'HTTP':
            return None
        try:
            return self.octodns['healthcheck']['tls']
        except KeyError:
            return False

    @property
    def healthcheck_timeout(self):
        """Gcore API field : meta['failover']['timeout']"""
        try:
            return self.octodns['healthcheck']['timeout']
        except KeyError:
            return 10


class GCoreClient(object):
    ROOT_ZONES = "zones"

    def __init__(
        self,
        log,
        api_url,
        auth_url,
        token=None,
        token_type=None,
        login=None,
        password=None,
    ):
        self.log = log
        self._session = Session()
        self._session.headers.update(
            {
                'User-Agent': f'octodns/{octodns_version} octodns-gcore/{__VERSION__}'
            }
        )
        self._api_url = api_url
        if token is not None and token_type is not None:
            self._session.headers.update(
                {"Authorization": f"{token_type} {token}"}
            )
        elif login is not None and password is not None:
            token = self._auth(auth_url, login, password)
            self._session.headers.update({"Authorization": f"Bearer {token}"})
        else:
            raise ValueError("either token or login & password must be set")

    def _auth(self, url, login, password):
        # well, can't use _request, since API returns 400 if credentials
        # invalid which will be logged, but we don't want do this
        r = self._session.request(
            "POST",
            self._build_url(url, "auth", "jwt", "login"),
            json={"username": login, "password": password},
        )
        r.raise_for_status()
        return r.json()["access"]

    def _request(self, method, url, params=None, data=None):
        r = self._session.request(
            method, url, params=params, json=data, timeout=30.0
        )
        if r.status_code == http.HTTPStatus.BAD_REQUEST:
            self.log.error(
                "bad request %r has been sent to %r: %s", data, url, r.text
            )
            raise GCoreClientBadRequest(r)
        elif r.status_code == http.HTTPStatus.NOT_FOUND:
            self.log.error("resource %r not found: %s", url, r.text)
            raise GCoreClientNotFound(r)
        elif r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
            self.log.error("server error no %r to %r: %s", data, url, r.text)
            raise GCoreClientException(r)
        r.raise_for_status()
        return r

    def zone(self, zone_name):
        return self._request(
            "GET", self._build_url(self._api_url, self.ROOT_ZONES, zone_name)
        ).json()

    def zone_create(self, zone_name):
        return self._request(
            "POST",
            self._build_url(self._api_url, self.ROOT_ZONES),
            data={"name": zone_name},
        ).json()

    def zone_records(self, zone_name):
        url = self._build_url(
            self._api_url, self.ROOT_ZONES, zone_name, "rrsets"
        )
        rrsets = self._request("GET", url, params={"all": "true"}).json()
        records = rrsets["rrsets"]
        return records

    def record_create(self, zone_name, rrset_name, type_, data):
        # change ALIAS records to CNAME
        if type_ == 'ALIAS':
            type_ = 'CNAME'
        self._request(
            "POST", self._rrset_url(zone_name, rrset_name, type_), data=data
        )

    def record_update(self, zone_name, rrset_name, type_, data):
        # change ALIAS records to CNAME
        if type_ == 'ALIAS':
            type_ = 'CNAME'
        self._request(
            "PUT", self._rrset_url(zone_name, rrset_name, type_), data=data
        )

    def record_delete(self, zone_name, rrset_name, type_):
        # change ALIAS records to CNAME
        if type_ == 'ALIAS':
            type_ = 'CNAME'
        self._request("DELETE", self._rrset_url(zone_name, rrset_name, type_))

    def _rrset_url(self, zone_name, rrset_name, type_):
        return self._build_url(
            self._api_url, self.ROOT_ZONES, zone_name, rrset_name, type_
        )

    @staticmethod
    def _build_url(base, *items):
        for i in items:
            base = base.strip("/") + "/"
            base = urllib.parse.urljoin(base, i)
        return base


class _BaseProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = True
    SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        ("A", "AAAA", "ALIAS", "CAA", "NS", "MX", "TXT", "SRV", "CNAME", "PTR")
    )

    def __init__(self, id, api_url, auth_url, *args, **kwargs):
        token = kwargs.pop("token", None)
        token_type = kwargs.pop("token_type", "APIKey")
        login = kwargs.pop("login", None)
        password = kwargs.pop("password", None)
        self.records_per_response = kwargs.pop("records_per_response", 1)
        self.log.debug("__init__: id=%s", id)
        super().__init__(id, *args, **kwargs)
        self._client = GCoreClient(
            self.log,
            api_url,
            auth_url,
            token=token,
            token_type=token_type,
            login=login,
            password=password,
        )

    def _add_dot_if_need(self, value):
        return f"{value}." if not value.endswith(".") else value

    def _build_pools(self, record, default_pool_name, value_transform_fn):
        defaults = []
        geo_sets, pool_idx = dict(), 0
        pools = defaultdict(lambda: {"values": []})
        for rr in record["resource_records"]:
            meta = rr.get("meta", {}) or {}
            value = {"value": value_transform_fn(rr["content"][0])}
            countries = meta.get("countries", []) or []
            continents = meta.get("continents", []) or []

            if meta.get("default", False):
                pools[default_pool_name]["values"].append(value)
                defaults.append(value["value"])
                continue
            # defaults is false or missing and no conties or continents
            elif len(continents) == 0 and len(countries) == 0:
                defaults.append(value["value"])
                continue

            # RR with the same set of countries and continents are
            # combined in single pool
            geo_set = frozenset(
                [GeoCodes.country_to_code(cc.upper()) for cc in countries]
            ) | frozenset(cc.upper() for cc in continents)
            if geo_set not in geo_sets:
                geo_sets[geo_set] = f"pool-{pool_idx}"
                pool_idx += 1

            pools[geo_sets[geo_set]]["values"].append(value)

        return pools, geo_sets, defaults

    def _build_rules(self, pools, geo_sets):
        rules = []
        for name, _ in pools.items():
            rule = {"pool": name}
            geo_set = next(
                (
                    geo_set
                    for geo_set, pool_name in geo_sets.items()
                    if pool_name == name
                ),
                {},
            )
            if len(geo_set) > 0:
                rule["geos"] = list(geo_set)
            rules.append(rule)

        return sorted(rules, key=lambda x: x["pool"])

    def _data_for_dynamic_geo(self, record, value_transform_fn=lambda x: x):
        default_pool = "other"
        pools, geo_sets, defaults = self._build_pools(
            record, default_pool, value_transform_fn
        )
        if len(pools) == 0:
            raise RuntimeError(
                f"filter is enabled, but no pools where built for {record}"
            )

        # defaults can't be empty, so use first pool values
        if len(defaults) == 0:
            defaults = [
                value_transform_fn(v["value"])
                for v in next(iter(pools.values()))["values"]
            ]

        # if at least one default RR was found then setup fallback for
        # other pools to default
        if default_pool in pools:
            for pool_name, pool in pools.items():
                if pool_name == default_pool:
                    continue
                pool["fallback"] = default_pool

        rules = self._build_rules(pools, geo_sets)
        return pools, rules, defaults

    def _data_for_single(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "value": self._add_dot_if_need(
                record["resource_records"][0]["content"][0]
            ),
        }

    _data_for_PTR = _data_for_single
    _data_for_ALIAS = _data_for_single

    def _data_for_CNAME(self, _type, record):
        if record.get("filters") is None:
            return self._data_for_single(_type, record)

        pools, rules, defaults = self._data_for_dynamic_geo(
            record, self._add_dot_if_need
        )
        return {
            "ttl": record["ttl"],
            "type": _type,
            "dynamic": {"pools": pools, "rules": rules},
            "value": self._add_dot_if_need(defaults[0]),
        }

    def _data_for_multiple(self, _type, record):
        extra = dict()
        filters = record.get("filters")
        if filters is not None:
            filter_types = [filter['type'] for filter in filters]
            if 'geodns' in filter_types:
                pools, rules, defaults = self._data_for_dynamic_geo(record)
                extra = {
                    "dynamic": {"pools": pools, "rules": rules},
                    "values": defaults,
                }
            else:
                # other type should be "healthcheck"
                pools, rules, octodns, defaults = (
                    self._data_dynamic_healthcheck(record)
                )
                extra = {
                    'dynamic': {'pools': pools, 'rules': [{'pool': 'pool-0'}]},
                    'octodns': octodns,
                    "values": defaults,
                }
        else:
            extra = {
                "values": [
                    rr_value
                    for resource_record in record["resource_records"]
                    for rr_value in resource_record["content"]
                ]
            }
        return {"ttl": record["ttl"], "type": _type, **extra}

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_TXT(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "values": [
                rr_value.replace(";", "\\;")
                for resource_record in record["resource_records"]
                for rr_value in resource_record["content"]
            ],
        }

    def _data_for_MX(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "values": [
                dict(
                    preference=preference,
                    exchange=self._add_dot_if_need(exchange),
                )
                for preference, exchange in map(
                    lambda x: x["content"], record["resource_records"]
                )
            ],
        }

    def _data_for_NS(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "values": [
                self._add_dot_if_need(rr_value)
                for resource_record in record["resource_records"]
                for rr_value in resource_record["content"]
            ],
        }

    def _data_for_SRV(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "values": [
                dict(
                    priority=priority,
                    weight=weight,
                    port=port,
                    target=self._add_dot_if_need(target),
                )
                for priority, weight, port, target in map(
                    lambda x: x["content"], record["resource_records"]
                )
            ],
        }

    def _data_for_CAA(self, _type, record):
        return {
            "ttl": record["ttl"],
            "type": _type,
            "values": [
                dict(flags=flags, tag=tag, value=value)
                for flags, tag, value in map(
                    lambda x: x["content"], record["resource_records"]
                )
            ],
        }

    def _data_dynamic_healthcheck(self, record):

        check_params = record['meta']['failover']

        defaults = [
            resource['content'][0] for resource in record["resource_records"]
        ]

        pools = {
            'pool-0': {
                'values': [
                    {
                        'value': resource['content'][0],
                        'status': 'obey',
                        # 'status': 'up' if resource['enabled'] else 'down',
                    }
                    for resource in record["resource_records"]
                ]
            }
        }
        octodns = {
            'healthcheck': {
                'host': check_params['host'],
                # path properties is associated with url gcore param
                'path': check_params['url'],
                'port': check_params['port'],
                'protocol': check_params['protocol'],
                'frequency': check_params['frequency'],
                'http_status_code': check_params['http_status_code'],
                'method': check_params['method'],
                'regexp': check_params['regexp'],
                'timeout': check_params['timeout'],
                'tls': check_params['tls'],
            }
        }
        rules = [{'pool': 'pool-0'}]
        self.log.debug('_data_dynamic_healthcheck = %s', str(octodns))

        return pools, rules, octodns, defaults

    def zone_records(self, zone):
        try:
            return self._client.zone_records(zone.name[:-1]), True
        except GCoreClientNotFound:
            return [], False

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(defaultdict)
        records, exists = self.zone_records(zone)
        for record in records:
            rr_name = zone.hostname_from_fqdn(record["name"])
            _type = record["type"].upper()
            if _type == 'CNAME' and rr_name == '':
                _type = 'ALIAS'
            if _type not in self.SUPPORTS:
                continue
            if self._should_ignore(record):
                continue
            values[rr_name][_type] = record

        before = len(zone.records)
        for name, types in values.items():
            for _type, record in types.items():
                data_for = getattr(self, f"_data_for_{_type}")
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, record),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        self.log.info(
            "populate:   found %s records, exists=%s",
            len(zone.records) - before,
            exists,
        )
        return exists

    def _should_ignore(self, record):
        name = record.get("name", "name-not-defined")
        if record.get("filters") is None:
            return False
        filters = record.get("filters", [])
        types = [v.get("type") for v in filters]

        if 'healthcheck' in types or ' ' in types:
            return False

        want_filters = 3
        if len(filters) != want_filters:
            self.log.info(
                "ignore %s has filters and their count is not %d",
                name,
                want_filters,
            )
            return True
        for i, want_type in enumerate(["geodns", "default", "first_n"]):
            if types[i] != want_type:
                self.log.info(
                    "ignore %s, filters.%d.type is %s, want %s",
                    name,
                    i,
                    types[i],
                    want_type,
                )
                return True
        limits = [filters[i].get("limit", 1) for i in [1, 2]]
        if limits[0] != limits[1]:
            self.log.info(
                "ignore %s, filters.1.limit (%d) != filters.2.limit (%d)",
                name,
                limits[0],
                limits[1],
            )
            return True
        return False

    def _params_for_dynamic_healthcheck(self, record):
        """Return ressource records for dynamic healthcheck dynamic records

        Cf. https://api.gcore.com/docs/dns#tag/RRsets/operation/UpdateRRSet

        Args:
            record (Record): _description_

        Returns:
            Resource_records: Array of objects (InputResourceRecord) [ items ]
        """

        resource_records = []

        for value in record.dynamic.pools['pool-0'].data["values"]:
            v = value["value"]
            resource_records.append(
                {"content": [v], "enabled": True, "meta": {}}
            )
        return resource_records

    def _params_for_dynamic_geo(self, record):
        records = []
        default_pool_found = False
        default_values = set(
            record.values if hasattr(record, "values") else [record.value]
        )
        for rule in record.dynamic.rules:
            meta = dict()
            # build meta tags if geos information present
            if len(rule.data.get("geos", [])) > 0:
                for geo_code in rule.data["geos"]:
                    geo = GeoCodes.parse(geo_code)

                    country = geo["country_code"]
                    continent = geo["continent_code"]
                    if country is not None:
                        meta.setdefault("countries", []).append(country)
                    else:
                        meta.setdefault("continents", []).append(continent)
            else:
                meta["default"] = True

            pool_values = set()
            pool_name = rule.data["pool"]
            for value in record.dynamic.pools[pool_name].data["values"]:
                v = value["value"]
                records.append({"content": [v], "meta": meta})
                pool_values.add(v)

            default_pool_found |= default_values == pool_values

        # if default values doesn't match any pool values, then just add this
        # values with no any meta
        if not default_pool_found:
            for value in default_values:
                records.append({"content": [value]})

        return records

    def _params_for_single(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [{"content": [record.value]}],
        }

    _params_for_PTR = _params_for_single
    _params_for_ALIAS = _params_for_single

    def _params_for_CNAME(self, record):
        if not record.dynamic:
            return self._params_for_single(record)

        return {
            "ttl": record.ttl,
            "resource_records": self._params_for_dynamic_geo(record),
            "filters": [
                {"type": "geodns"},
                {
                    "type": "default",
                    "limit": self.records_per_response,
                    "strict": False,
                },
                {"type": "first_n", "limit": self.records_per_response},
            ],
        }

    def _params_for_multiple(self, record):
        extra = dict()
        # If the Record is an healthcheck dynamic record
        if record.octodns.get('healthcheck'):

            healthcheck = record.octodns['healthcheck']
            # path is translated to url for Gcore API
            healthcheck['url'] = healthcheck['path']

            extra['meta'] = {'failover': healthcheck}

            # meta = (
            #     {
            #         "failover": {
            #             "frequency": 180,
            #             "host": "gcore-test.tld",
            #             "http_status_code": 200,
            #             "method": "GET",
            #             "port": 80,
            #             "protocol": "HTTP",
            #             "regexp": "ok",
            #             "timeout": 10,
            #             "tls": False,
            #             "url": "/ns1-monitor",
            #         }
            #     },
            # )
            extra['pickers'] = [
                {"type": "healthcheck", "strict": False},
                {"type": "weighted_shuffle", "strict": False},
            ]

            extra["resource_records"] = self._params_for_dynamic_healthcheck(
                record
            )

        # If the Record is a GeoDNS dynamic record
        elif record.dynamic:
            extra["resource_records"] = self._params_for_dynamic_geo(record)
            extra["filters"] = [
                {"type": "geodns"},
                {
                    "type": "default",
                    "limit": self.records_per_response,
                    "strict": False,
                },
                {"type": "first_n", "limit": self.records_per_response},
            ]
        else:
            extra["resource_records"] = [
                {"content": [value]} for value in record.values
            ]

        return {"ttl": record.ttl, **extra}

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_NS(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [
                {"content": [value]} for value in record.values
            ],
        }

    def _params_for_TXT(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [
                {"content": [value.replace("\\;", ";")]}
                for value in record.values
            ],
        }

    def _params_for_MX(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [
                {"content": [rec.preference, rec.exchange]}
                for rec in record.values
            ],
        }

    def _params_for_SRV(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [
                {"content": [rec.priority, rec.weight, rec.port, rec.target]}
                for rec in record.values
            ],
        }

    def _params_for_CAA(self, record):
        return {
            "ttl": record.ttl,
            "resource_records": [
                {"content": [rec.flags, rec.tag, rec.value]}
                for rec in record.values
            ],
        }

    def _apply_create(self, change):
        self.log.info("creating: %s", change)
        new = change.new
        data = getattr(self, f"_params_for_{new._type}")(new)
        self._client.record_create(
            new.zone.name[:-1], new.fqdn, new._type, data
        )

    def _apply_update(self, change):
        self.log.info("updating: %s", change)
        new = change.new
        data = getattr(self, f"_params_for_{new._type}")(new)
        self.log.debug("updating: %s", str(data))
        self._client.record_update(
            new.zone.name[:-1], new.fqdn, new._type, data
        )

    def _apply_delete(self, change):
        self.log.info("deleting: %s", change)
        existing = change.existing
        self._client.record_delete(
            existing.zone.name[:-1], existing.fqdn, existing._type
        )

    def _extra_changes(self, existing, desired, changes):
        self.log.debug(
            "_extra_changes: existing=%s, desired=%s, (changes)=%d",
            existing.name,
            desired.name,
            len(changes),
        )
        '''
        An opportunity for providers to add extra changes to the plan that are
        necessary to update ancillary record data or configure the zone. E.g.
        base NS records.
        '''
        extra = []
        desired_records = {r: r for r in desired.records}
        changed = set([c.record for c in changes])

        for record in existing.records:
            if not getattr(record, 'dynamic', False):
                # no need to check non-dynamic simple records
                continue

            update = False

            desired_record = desired_records[record]
            if record.octodns == desired_record.octodns:
                continue
            update = True

            self.log.debug(
                "_extra_changes: Existing record=%s, \noctodns=%s",
                str(record.fqdn),
                str(record.octodns),
            )
            self.log.debug(
                "_extra_changes: Desired record=%s, \noctodns=%s",
                str(desired_record.fqdn),
                str(desired_record.octodns),
            )
            if update and record not in changed:
                extra.append(Update(record, desired_record))

        return extra

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone = desired.name[:-1]
        self.log.debug(
            "_apply: zone=%s, len(changes)=%d", desired.name, len(changes)
        )

        try:
            self._client.zone(zone)
        except GCoreClientNotFound:
            self.log.info("_apply: no existing zone, trying to create it")
            self._client.zone_create(zone)
            self.log.info("_apply: zone has been successfully created")

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f"_apply_{class_name.lower()}")(change)

    def _process_desired_zone(self, desired):
        for record in desired.records:
            if getattr(record, "dynamic", False):
                dynamic = record.dynamic
                rules = []
                for index, rule in enumerate(dynamic.rules):
                    geos = rule.data.get("geos", [])
                    if not geos:
                        rules.append(rule)
                        continue
                    filtered_geos = [
                        g
                        for g in geos
                        if not g.startswith('NA-US-')
                        and not g.startswith("NA-CA-")
                    ]
                    if not filtered_geos:
                        msg = f'NA-US- and NA-CA-* not supported for {record.fqdn}'
                        fallback = f'skipping rule {index}'
                        self.supports_warn_or_except(msg, fallback)
                        continue
                    elif geos != filtered_geos:
                        msg = f'NA-US- and NA-CA-* not supported for {record.fqdn}'
                        before = ', '.join(geos)
                        after = ', '.join(filtered_geos)
                        fallback = (
                            f'filtering rule {index} from ({before}) to '
                            f'({after})'
                        )
                        self.supports_warn_or_except(msg, fallback)
                        rule.data['geos'] = filtered_geos
                    rules.append(rule)

                if rules != dynamic.rules:
                    record = record.copy()
                    record.dynamic.rules = rules
                    desired.add_record(record, replace=True)
            elif getattr(record, "geo", False):
                geos = set(record.geo.keys())
                filtered_geos = {
                    g
                    for g in geos
                    if not g.startswith('NA-US-') and not g.startswith("NA-CA-")
                }
                if not filtered_geos:
                    msg = f'NA-US- and NA-CA-* not supported for {record.fqdn}'
                    fallback = 'skipping rule 0'
                    self.supports_warn_or_except(msg, fallback)
                elif geos != filtered_geos:
                    msg = f'NA-US- and NA-CA-* not supported for {record.fqdn}'
                    before = ', '.join(geos)
                    after = ', '.join(filtered_geos)
                    fallback = f'filtering rule 0 from ({before}) to ({after})'
                    self.supports_warn_or_except(msg, fallback)
                if geos != filtered_geos:
                    record = record.copy()
                    new_geo = {
                        geo: value
                        for geo, value in record.geo.items()
                        if geo in filtered_geos
                    }
                    record.geo = new_geo
                    desired.add_record(record, replace=True)
        return super()._process_desired_zone(desired)


class GCoreProvider(_BaseProvider):
    def __init__(self, id, *args, **kwargs):
        self.log = logging.getLogger(f"GCoreProvider[{id}]")
        api_url = kwargs.pop("url", "https://api.gcore.com/dns/v2")
        auth_url = kwargs.pop("auth_url", "https://api.gcore.com/id")
        super().__init__(id, api_url, auth_url, *args, **kwargs)
