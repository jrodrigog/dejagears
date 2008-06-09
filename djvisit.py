import datetime
from turbogears.visit.api import BaseVisitManager, Visit
from turbogears.database import PackageHub
from turbogears import config
from turbogears.util import load_class
from dejavu import Unit, UnitProperty, UnitSequencer
import turbogears
import dejavu

hub = PackageHub("turbogears.visit")
__connection__ = hub

import logging

log = logging.getLogger("turbogears.visit")

visit_class = None

class DejavuVisitManager(BaseVisitManager):
    def __init__(self, timeout):
        global visit_class
        visit_class_path = config.get("visit.djprovider.model", __name__ + ".TG_Visit")
        visit_class = load_class(visit_class_path)
        if visit_class:
            log.info("Succesfully loaded \"%s\"" % visit_class_path)
        super(DejavuVisitManager,self).__init__( timeout )

    def create_model(self):
        global visit_class
        try:
            arena = hub.getConnection().arena
            if not arena._registered_classes.has_key( visit_class ):
                arena.register( visit_class )
                if not arena.has_storage( visit_class ):
                    arena.create_storage( visit_class )
        except Exception, e:
            # No database configured...
            log.info( "No database is configured: Visit Tracking is disabled. " + str( e ) )

    def new_visit_with_key(self, visit_key):
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        now = datetime.datetime.now()
        visit = visit_class( visit_key=visit_key, expiry = now + self.timeout, created = now )
        box.memorize( visit )
        box.flush_all()
        return Visit( visit_key, True )

    def visit_for_key(self, visit_key):
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        visit = box.unit( visit_class, visit_key=visit_key )
        box.flush_all()
        now = datetime.datetime.now()
        if not visit or visit.expiry < now:
            return None
        # Visit hasn't expired, extend it
        self.update_visit( visit_key, now+self.timeout )
        return Visit( visit_key, False )

    def update_queued_visits(self, queue):
        if hub is None: # if VisitManager extension wasn't shutted down cleanly
            return
        box = hub.getConnection()
        box.start( isolation = turbogears.database.REPEATABLE_READ )
        try:
            try:
                # Now update each of the visits with the most recent expiry
                for visit_key,expiry in queue.items():
                    visit = box.unit( visit_class, visit_key = visit_key )
                    visit.expiry = expiry
                box.commit()
            except:
                box.rollback()
                raise
        finally:
            box.flush_all()

class TG_Visit( Unit ):
    visit_key = UnitProperty( str, index=True, hints={"bytes":40} )
    created = UnitProperty( datetime.datetime )
    expiry = UnitProperty( datetime.datetime )
    ID = None
    identifiers = ("visit_key",)
    sequencer = UnitSequencer()

    def lookup_visit( cls, visit_key ):
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        visit = box.unit( visit_class, visit_key = visit_key )
        box.flush_all()
        return visit
    lookup_visit = classmethod( lookup_visit )

