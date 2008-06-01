"""Provides convenient access to an SQLObject or SQLAlchemy
managed database."""
import logging, dejavu, cherrypy, dispatch, atexit
from turbogears import config
from cherrypy.filters.basefilter import BaseFilter
from turbogears.genericfunctions import MultiorderGenericFunction
from dejavu import logflags
try:
    from sqlobject.util.threadinglocal import local as threading_local
except ImportError:
    from threading import local as threading_local

_arena = None
def _arena_shutdown():
    global _arena
    if _arena:
        log.info("Arena shutdown...")
        _arena.shutdown()
atexit.register( _arena_shutdown )

try:
    set
except NameError:
    from sets import Set as set

hub_registry = set()
_hubs = dict()
_stores = dict()

READ_UNCOMMITTED = dejavu.storage.isolation.READ_UNCOMMITTED
READ_COMMITTED = dejavu.storage.isolation.READ_COMMITTED
REPEATABLE_READ = dejavu.storage.isolation.REPEATABLE_READ
SERIALIZABLE = dejavu.storage.isolation.SERIALIZABLE

log = logging.getLogger("turbogears.database")

class AutoConnectHub(object): # ConnectionHub
    """Connects to the database once per thread. The AutoConnectHub also
    provides convenient methods for managing transactions."""
    uri = None
    params = {}

    def __init__(self, uri=None, supports_transactions=True):
        if not uri:
            uri = config.get("dejavu.dburi")
        self.uri = uri
        self.supports_transactions = supports_transactions
        self.threadingLocal = threading_local()
        hub_registry.add(self)

    def getConnection(self):
        global _arena, _stores
        try:
            self.threadingLocal.boxes[ self.uri ]
        except ( AttributeError, KeyError ):
            if not _arena:
                log.info("Arena startup...")
                _arena = dejavu.Arena()
                #_arena.logflags = logflags.ERROR + logflags.SQL # + logflags.SANDBOX + logflags.IO
            if not _stores.has_key( self.uri ):
                 log.info("New store: %s" % self.uri )
                 _arena.load( self.uri )
                 _stores[ self.uri ] = True
                 #arena.stores[ self.uri ].auto_discover = False
            try:
                self.threadingLocal.boxes
            except AttributeError:
                self.threadingLocal.boxes = {}
            self.threadingLocal.boxes[ self.uri ] = self.begin( _arena.new_sandbox() )
        return self.threadingLocal.boxes[ self.uri ]
        
    def reset(self):
        """Used for testing purposes. This drops all of the connections
        that are being held."""
        self.threadingLocal = threading_local()

    def begin(self, conn=None):
        "Starts a transaction."
        if not self.supports_transactions:
            return conn
        if not conn:
            conn = self.getConnection()
        conn.start( isolation=READ_COMMITTED )
        return conn

    def commit(self):
        "Commits the current transaction."
        if not self.supports_transactions:
            return
        try:
            conn = self.threadingLocal.boxes[ self.uri ]
        except  ( AttributeError, KeyError ):
            return
        conn.commit()

    def rollback(self):
        "Rolls back the current transaction."
        if not self.supports_transactions:
            return
        try:
            conn = self.threadingLocal.boxes[ self.uri ]
        except  ( AttributeError, KeyError ):
            return
        conn.rollback()

    def end(self):
        "Ends the transaction, returning to a standard connection."
        if not self.supports_transactions:
            return
        try:
            conn = self.threadingLocal.boxes[ self.uri ]
        except  ( AttributeError, KeyError ):
            return
        conn.flush_all()

class PackageHub(object):
    """Transparently proxies to an AutoConnectHub for the URI
    that is appropriate for this package. A package URI is
    configured via "packagename.dburi" in the global CherryPy
    settings. If there is no package DB URI configured, the
    default (provided by "sqlobject.dburi") is used.

    The hub is not instantiated until an attempt is made to
    use the database.
    """
    def __init__(self, packagename):
        self.packagename = packagename
        self.hub = None

    def __get__(self, obj, type):
        if not self.hub:
            self.set_hub()
        return self.hub.__get__(obj, type)

    def __set__(self, obj, type):
        if not self.hub:
            self.set_hub()
        return self.hub.__set__(obj, type)

    def __getattr__(self, name):
        if not self.hub:
            self.set_hub()
        return getattr(self.hub, name)

    def set_hub(self):
        dburi = config.get("%s.dburi" % self.packagename, None)
        if not dburi:
            dburi = config.get("dejavu.dburi", None)
        if not dburi:
            raise KeyError, "No database configuration found!"
        if dburi.startswith("notrans_"):
            dburi = dburi[8:]
            trans = False
        else:
            trans = True
        hub = _hubs.get(dburi, None)
        if not hub:
            hub = AutoConnectHub(dburi, supports_transactions=trans)
            _hubs[dburi] = hub
        self.hub = hub

def set_db_uri(dburi, package=None):
    """Sets the database URI to use either globally or for a specific
    package. Note that once the database is accessed, calling
    setDBUri will have no effect.

    @param dburi: database URI to use
    @param package: package name this applies to, or None to set the default.
    """
    if package:
        config.update({'global':
            {"%s.dburi" % package : dburi}
        })
    else:
        config.update({'global':
            {"dejavu.dburi" : dburi}
        })

def commit_all():
    "Commits the Transactions in all registered hubs (for this thread)"
    for hub in hub_registry:
        hub.commit()

def rollback_all():
    "Rolls back the Transactions in all registered hubs (for this thread)"
    for hub in hub_registry:
        hub.rollback()

def end_all():
    "Ends the Transactions in all registered hubs (for this thread)"
    for hub in hub_registry:
        hub.end()

def _use_sa(args=None):
    return False

[dispatch.generic(MultiorderGenericFunction)]
def run_with_transaction(func, *args, **kw):
    pass

[dispatch.generic(MultiorderGenericFunction)]
def restart_transaction(args):
    pass

# include "args" to avoid call being pre-cached
[restart_transaction.when("not _use_sa(args)")]
def so_restart_transaction(args):
    #log.debug("ReStarting SQLObject transaction")
    # Disable for now for compatibility
    pass

[run_with_transaction.when("not _use_sa(args)")] # include "args" to avoid call being pre-cached
def so_rwt(func, *args, **kw):
    log.debug("Starting Dejavu transaction")
    try:
        try:
            retval = func(*args, **kw)
            commit_all()
            return retval
        except cherrypy.HTTPRedirect:
            commit_all()
            raise
        except cherrypy.InternalRedirect:
            commit_all()
            raise
        except:
            rollback_all()
            raise
    finally:
        end_all()


def so_to_dict(unit):
    "Converts a Dejavu unit to a dictionary based on columns"
    return dict( zip( unit.properties, [ getattr( unit, property ) for property in unit.properties ] ) )

def so_columns(sqlclass, columns=None):
    """Returns a dict with all columns from a SQLObject including those from
    InheritableSO's bases"""
    raise NotImplementedError

def so_joins(sqlclass, joins=None):
    """Returns a list with all joins from a SQLObject including those from
    InheritableSO's bases"""
    raise NotImplementedError

class EndTransactionsFilter(BaseFilter):
    def on_end_resource(self):
        rollback_all()
        end_all()
        
__all__ = ["PackageHub", "AutoConnectHub", "set_db_uri",
           "commit_all", "rollback_all", "end_all", "so_to_dict",
           "so_columns", "so_joins", "EndTransactionsFilter"]
