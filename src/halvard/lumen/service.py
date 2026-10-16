"""Lumen: AI tools (inventory, data policy) and AI agents (inventory, gateway, audit) as one module of the control plane."""
from pathlib import Path

from .agents import AgentRegistry
from .gateway import AgentGateway, ReferenceTools
from .inventory import AIInventory, load_catalog


class LumenService:
    def __init__(self, store, ctx, clock, audit, idp, aws, signet, catalog_path, tools_key=b"lumen-tool-grant-key-0123456789", inspector=None, internal_domains=()):
        self.store, self.ctx, self.clock, self.audit = store, ctx, clock, audit
        cat = load_catalog(catalog_path) if Path(catalog_path).exists() else []
        self.inventory = AIInventory(cat, audit, clock)
        self.registry = AgentRegistry(clock, audit, idp, aws, signet)
        self.tools = ReferenceTools(tools_key, clock)
        self.gateway = AgentGateway(self.registry, self.tools, clock, audit, inspector, internal_domains=internal_domains)

    def sync_graph(self):
        """AI agents are graph entities that act for their owner, so a case about an agent lands in the same neighbourhood as the person."""
        now, S, c = self.clock.now(), self.store, self.ctx
        for a in self.registry.agents.values():
            eid = f"ai:{a.id}"
            if not S.has_entity(c, eid): S.put_entity(c, eid, "ai_agent", a.name, now, asset_class="standard", should_be_protected=0, attrs={"owner": a.owner, "tier": a.tier, "identity": a.identity})
            else: S.update_entity(c, eid, now, attrs={"owner": a.owner, "tier": a.tier, "identity": a.identity})
            if a.owner and S.has_entity(c, a.owner): S.put_edge(c, eid, "acts_for", a.owner, now)

    def poll(self):
        self.registry.discover_identities(); self.sync_graph()
        return self.gateway.poll()
