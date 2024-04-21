#
#
#

from logging import getLogger

from octodns.provider.base import BaseProvider
from octodns.record import Record, SshfpRecord, Update

from octodns_selectel.version import __version__ as provider_version

from .dns_client import DNSClient
from .exceptions import ApiException
from .mappings import to_octodns_record_data, to_selectel_rrset


class SelectelProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS = set(
        ('A', 'AAAA', 'ALIAS', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SSHFP', 'DNAME')
    )
    MIN_TTL = 60

    def __init__(self, id, token, *args, **kwargs):
        self.log = getLogger(f'SelectelProvider[{id}]')
        self.log.debug('__init__: id=%s', id)
        super().__init__(id, *args, **kwargs)
        self._client = DNSClient(provider_version, token)
        self._zone_rrsets = {}
        self._zones = None

    def _include_change(self, change):
        if isinstance(change, Update):
            existing = change.existing.data
            new = change.new.data
            new['ttl'] = max(self.MIN_TTL, new['ttl'])
            if isinstance(change.new, SshfpRecord):
                for i in range(0, len(change.new.rr_values)):
                    change.new.rr_values[i].fingerprint = \
                        change.new.rr_values[i].fingerprint.lower()
            if 'values' in existing and 'values' in new:
                existing = {'ttl': existing['ttl'], 'values': sorted(existing['values'])}
                new = {'ttl': new['ttl'], 'values': sorted(new['values'])}
            if new == existing:
                self.log.debug('_include_change: %s -> %s', new, existing)
                return False
        return True

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        zone_name = desired.decoded_name
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', zone_name, len(changes)
        )
        if not self.zone_exists(desired):
            self.create_zone(desired)

        zone_id = self._get_zone_id(desired)
        for change in changes:
            action = change.__class__.__name__.lower()
            if action == 'create':
                self._apply_create(zone_id, change)
            if action == 'update':
                self._apply_update(zone_id, change)
            if action == 'delete':
                self._apply_delete(zone_id, change)

        # invalidate cache
        self._zone_rrsets.pop(zone_name, None)

    def _get_rrset_id(self, zone, rrset_type, rrset_name):
        self.log.debug(f'_get_rrset_id: {zone}, {rrset_type}, {rrset_name}')
        return next(
            filter(
                lambda rrset: rrset["type"] == rrset_type
                and rrset["name"] == rrset_name,
                self.list_rrsets(zone),
            )
        )["id"]

    def _apply_create(self, zone_id, change):
        self.log.debug(f'_apply_create: {zone_id} for {change.new}')
        new_record = change.new
        rrset = to_selectel_rrset(new_record)
        return self._client.create_rrset(zone_id, rrset)

    def _apply_update(self, zone_id, change):
        self.log.debug(f'_apply_update: {zone_id} or {change.new}')
        existing = change.existing
        rrset_id = self._get_rrset_id(
            existing.zone,
            existing._type,
            existing.decoded_fqdn,
        )
        data = to_selectel_rrset(change.new)
        try:
            self._client.update_rrset(zone_id, rrset_id, data)
        except ApiException as api_exception:
            self.log.error(f'Failed to update rrset {rrset_id}. {api_exception}')

    def _apply_delete(self, zone_id, change):
        self.log.debug(f'_apply_delete: {zone_id} for {change.existing}')
        existing = change.existing
        rrset_id = self._get_rrset_id(
            existing.zone,
            existing._type,
            existing.decoded_fqdn,
        )
        try:
            self._client.delete_rrset(zone_id, rrset_id)
        except ApiException as api_exception:
            self.log.error(f'Failed to delete rrset {rrset_id}. {api_exception}')

    def list_zones(self):
        # This method is called dynamically in octodns.Manager._preprocess_zones()
        # and required for use of "*" if provider is source.
        return [zone_name for zone_name in self.zones]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.decoded_name,
            target,
            lenient,
        )
        before = len(zone.records)

        rrsets = []
        if self.zone_exists(zone):
            rrsets = self.list_rrsets(zone)

        for rrset in rrsets:
            rrset_type = rrset['type']
            if rrset_type in self.SUPPORTS:
                record_data = to_octodns_record_data(rrset)
                rrset_hostname = zone.hostname_from_fqdn(rrset['name'])
                record = Record.new(
                    zone,
                    rrset_hostname,
                    record_data,
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record)

        self.log.info('populate: found %s records', len(zone.records) - before)
        return bool(rrsets)

    @property
    def zones(self):
        self.log.debug(f'properety zones: {zone} called from {sys._getframe().f_back}')
        if self._zones is None:
            self.log.debug('View zones')
            self._zones = {zone['name']: zone for zone in self._client.list_zones()}
        return self._zones

    def _get_zone_id(self, zone):
        self.log.debug(f'_get_zone_id: {zone}')
        if self._zones and zone.decoded_name in self._zones:
            return self._zones[zone.decoded_name]["id"]
        for z in self._client.list_zones(filter=zone.decoded_name):
            if self._zones is None: self._zones = {}
            self._zones[z["name"]] = z
        return self._zones.get(zone.decoded_name, {}).get('id')

    def zone_exists(self, zone):
        self.log.debug(f'zone_exists: {zone}')
        return self._get_zone_id(zone) is not None

    def create_zone(self, zone):
        self.log.debug(f'create_zone: {zone}')
        zone = self._client.create_zone(zone.decoded_name)
        self._zones[zone["name"]] = zone
        return zone

    def list_rrsets(self, zone):
        self.log.debug(f'list_rrsets: {zone}')
        zone_name = zone.decoded_name
        if zone_name in self._zone_rrsets:
            return self._zone_rrsets[zone_name]
        zone_id = self._get_zone_id(zone)
        zone_rrsets = self._client.list_rrsets(zone_id)
        self._zone_rrsets[zone_name] = zone_rrsets
        return zone_rrsets
