"""Convenient access to an SQLObject or SQLAlchemy managed database."""

import sys
import time
import logging

import cherrypy
from cherrypy.filters.basefilter import BaseFilter
import turbogears

try:
    import dejavu
    import atexit
    from threading import local as threading_local
except ImportError:
    dejavu = None

try:
    import sqlalchemy, sqlalchemy.orm
    from sqlalchemy import MetaData
except ImportError:
    sqlalchemy = None

try:
    import sqlobject
    from sqlobject.dbconnection import ConnectionHub, Transaction, TheURIOpener
    from sqlobject.util.threadinglocal import local as threading_local
except ImportError:
    sqlobject = None

# This key is non existant (turbogears.orm)
# there could exist import issues with this approach
# right now dejavu is the default for testing pourposes
_orm = turbogears.config.get( "turbogears.orm", "dejavu" )
if _orm == "sqlobject":
    sqlalchemy = None
    dejavu = None
elif _orm == "sqlalchemy":
    sqlobject = None
    dejavu = None
elif _orm == "dejavu":
    sqlobject = None
    sqlalchemy = None

from peak.rules import abstract, when, NoApplicableMethods

from turbogears import config
from turbogears.util import remove_keys

log = logging.getLogger("turbogears.database")

_using_sa = False

# Provide support for SQLAlchemy
if sqlalchemy:

    def get_engine(pkg=None):
        """Retrieve the engine based on the current configuration."""
        bind_metadata()
        return get_metadata(pkg).bind

    def get_metadata(pkg=None):
        """Retrieve the metadata for the specified package."""
        try:
            return _metadatas[pkg]
        except KeyError:
            _metadatas[pkg] = MetaData()
            return _metadatas[pkg]

    def bind_metadata():
        """Connect SQLAlchemy to the configured database(s)."""
        if metadata.is_bound():
            return

        alch_args = dict()
        for k, v in config.config.configMap["global"].items():
            if "sqlalchemy" in k:
                alch_args[k.split(".")[-1]] = v

        dburi = alch_args.pop('dburi')
        if not dburi:
            raise KeyError("No sqlalchemy database config found!")
        metadata.bind = sqlalchemy.create_engine(dburi, **alch_args)

        global _using_sa
        _using_sa = True

        for k, v in config.config.configMap["global"].items():
            if ".dburi" in k and 'sqlalchemy.' not in k:
                get_metadata(k.split(".")[0]).bind = sqlalchemy.create_engine(v, **alch_args)

    def create_session():
        """Create a session that uses the engine from thread-local metadata."""
        if not metadata.is_bound():
            bind_metadata()
        return sqlalchemy.orm.create_session()

    try:
        session = sqlalchemy.orm.scoped_session(create_session)
        mapper = session.mapper
    except AttributeError: # SQLAlchemy < 0.4
        from sqlalchemy.ext.sessioncontext import SessionContext
        class Objectstore(object):
            def __init__(self, *args, **kwargs):
                self.context = SessionContext(*args, **kwargs)
            def __getattr__(self, name):
                return getattr(self.context.current, name)
            def begin(self):
                self.create_transaction()
            def commit(self):
                if self.transaction:
                    self.transaction.commit()
            def rollback(self):
                if self.transaction:
                    self.transaction.rollback()
        session = Objectstore(create_session)
        context = session.context
        Query = sqlalchemy.Query
        from sqlalchemy.orm import mapper as orm_mapper
        def mapper(cls, *args, **kwargs):
            validate = kwargs.pop('validate', False)
            if not hasattr(getattr(cls, '__init__'), 'im_func'):
                def __init__(self, **kwargs):
                     for key, value in kwargs.items():
                         if validate and key not in self.mapper.props:
                             raise KeyError(
                                "Property does not exist: '%s'" % key)
                         setattr(self, key, value)
                cls.__init__ = __init__
            m = orm_mapper(cls, extension=context.mapper_extension,
                *args, **kwargs)
            class query_property(object):
                def __get__(self, instance, cls):
                    return Query(cls, session=context.current)
            cls.query = query_property()
            return m

    _metadatas = {}
    _metadatas[None] = MetaData()
    metadata = _metadatas[None]

    try:
        import elixir
        elixir.metadata, elixir.session = metadata, session
    except ImportError:
        pass

else:
    def get_engine():
        pass
    def get_metadata():
        pass
    def bind_metadata():
        pass
    def create_session():
        pass
    session = metadata = mapper = None

bind_meta_data = bind_metadata # deprecated, for backward compatibility

hub_registry = set()

_hubs = dict() # stores the AutoConnectHubs used for each connection URI

# Provide support for SQLObject
if sqlobject:
    def _mysql_timestamp_converter(raw):
        """Convert a MySQL TIMESTAMP to a floating point number representing
        the seconds since the Un*x Epoch. It uses custom code the input seems
        to be the new (MySQL 4.1+) timestamp format, otherwise code from the
        MySQLdb module is used."""
        if raw[4] == '-':
            return time.mktime(time.strptime(raw, '%Y-%m-%d %H:%M:%S'))
        else:
            import MySQLdb.converters
            return MySQLdb.converters.mysql_timestamp_converter(raw)


    class AutoConnectHub(ConnectionHub):
        """Connects to the database once per thread. The AutoConnectHub also
        provides convenient methods for managing transactions."""
        uri = None
        params = {}

        def __init__(self, uri=None, supports_transactions=True):
            if not uri:
                uri = config.get("sqlobject.dburi")
            self.uri = uri
            self.supports_transactions = supports_transactions
            hub_registry.add(self)
            ConnectionHub.__init__(self)

        def _is_interesting_version(self):
            """Return True only if version of MySQLdb <= 1.0."""
            import MySQLdb
            module_version = MySQLdb.version_info[0:2]
            major = module_version[0]
            minor = module_version[1]
            # we can't use Decimal here because it is only available for Python 2.4
            return (major < 1 or (major == 1 and minor < 2))

        def _enable_timestamp_workaround(self, connection):
            """Enable a workaround for an incompatible timestamp format change
            in MySQL 4.1 when using an old version of MySQLdb. See trac ticket
            #1235 - http://trac.turbogears.org/ticket/1235 for details."""
            # precondition: connection is a MySQLConnection
            import MySQLdb
            import MySQLdb.converters
            if self._is_interesting_version():
                conversions = MySQLdb.converters.conversions.copy()
                conversions[MySQLdb.constants.FIELD_TYPE.TIMESTAMP] = \
                    _mysql_timestamp_converter
                # There is no method to use custom keywords when using
                # "connectionForURI" in sqlobject so we have to insert the
                # conversions afterwards.
                connection.kw["conv"] = conversions

        def getConnection(self):
            try:
                conn = self.threadingLocal.connection
                return self.begin(conn)
            except AttributeError:
                if self.uri:
                    conn = sqlobject.connectionForURI(self.uri)
                    # the following line effectively turns off the DBAPI connection
                    # cache. We're already holding on to a connection per thread,
                    # and the cache causes problems with sqlite.
                    if self.uri.startswith("sqlite"):
                        TheURIOpener.cachedURIs = {}
                    elif self.uri.startswith("mysql") and \
                         config.get("turbogears.enable_mysql41_timestamp_workaround", False):
                        self._enable_timestamp_workaround(conn)
                    self.threadingLocal.connection = conn
                    return self.begin(conn)
                raise AttributeError(
                    "No connection has been defined for this thread "
                    "or process")

        def reset(self):
            """Used for testing purposes. This drops all of the connections
            that are being held."""
            self.threadingLocal = threading_local()

        def begin(self, conn=None):
            """Start a transaction."""
            if not self.supports_transactions:
                return conn
            if not conn:
                conn = self.getConnection()
            if isinstance(conn, Transaction):
                if conn._obsolete:
                    conn.begin()
                return conn
            self.threadingLocal.old_conn = conn
            trans = conn.transaction()
            self.threadingLocal.connection = trans
            return trans

        def commit(self):
            """Commit the current transaction."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.connection
            except AttributeError:
                return
            if isinstance(conn, Transaction):
                self.threadingLocal.connection.commit()

        def rollback(self):
            """Rollback the current transaction."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.connection
            except AttributeError:
                return
            if isinstance(conn, Transaction) and not conn._obsolete:
                self.threadingLocal.connection.rollback()

        def end(self):
            """End the transaction, returning to a standard connection."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.connection
            except AttributeError:
                return
            if not isinstance(conn, Transaction):
                return
            if not conn._obsolete:
                conn.rollback()
            self.threadingLocal.connection = self.threadingLocal.old_conn
            del self.threadingLocal.old_conn
            self.threadingLocal.connection.cache.clear()

# provide support for Dejavu
elif dejavu:
    _arena = None
    _stores = dict()

    READ_UNCOMMITTED = dejavu.storage.isolation.READ_UNCOMMITTED
    READ_COMMITTED = dejavu.storage.isolation.READ_COMMITTED
    REPEATABLE_READ = dejavu.storage.isolation.REPEATABLE_READ
    SERIALIZABLE = dejavu.storage.isolation.SERIALIZABLE

    def _arena_shutdown():
        global _arena
        if _arena:
            log.info("Arena shutdown...")
            _arena.shutdown()
    atexit.register( _arena_shutdown )

    class AutoConnectHub(object):
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
            """Returns the Dejavu SandBox"""
            global _arena, _stores
            uri_hash = ( self.uri, id( self.uri ) )[ isinstance( self.uri, dict ) ]
            try:
                return self.threadingLocal.boxes[ uri_hash ]
            except ( AttributeError, KeyError ):
                if not _arena:
                    log.info("Arena startup...")
                    _arena = dejavu.Arena()
                if isinstance( self.uri, dict ):
                    # Load a dictionary of dictionaries as the store configuration
                    for key in self.uri:
                        if not _stores.has_key( "store://" + key ):
                            try:
                                klass = self.uri[ key ][ "Class" ]
                                del self.uri[ key ][ "Class" ]
                                _arena.add_store( key, klass, self.uri[ key ] )
                                _stores[ "store://" + key ] = True
                                log.info("New store: %s" % key )
                            except KeyError:
                                log.error("Unknown class for store %s" % key )
                else:
                    # Load from a file, cache the file
                    if not _stores.has_key( "file://" + self.uri ):
                        _arena.load( self.uri )
                        _stores[ "file://" + self.uri ] = True
                        log.info("New store: %s" % self.uri )
                try:
                    self.threadingLocal.boxes
                except AttributeError:
                    self.threadingLocal.boxes = {}
                box = self.begin( _arena.new_sandbox() )
                self.threadingLocal.boxes[ uri_hash ] = box
            return box

        def reset(self):
            """Used for testing purposes. This drops all of the connections
            that are being held."""
            self.threadingLocal = threading_local()

        def begin(self, conn=None):
            """Starts a transaction."""
            if not self.supports_transactions:
                return conn
            if not conn:
                conn = self.getConnection()
            conn.start( isolation=READ_COMMITTED )
            return conn

        def commit(self):
            """Commits the current transaction."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.boxes[ ( self.uri, id( self.uri ) )[ isinstance( self.uri, dict ) ] ]
            except  ( AttributeError, KeyError ):
                return
            conn.commit()

        def rollback(self):
            """Rolls back the current transaction."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.boxes[ ( self.uri, id( self.uri ) )[ isinstance( self.uri, dict ) ] ]
            except  ( AttributeError, KeyError ):
                return
            conn.rollback()

        def end(self):
            """Ends the transaction, returning to a standard connection."""
            if not self.supports_transactions:
                return
            try:
                conn = self.threadingLocal.boxes[ ( self.uri, id( self.uri ) )[ isinstance( self.uri, dict ) ] ]
            except  ( AttributeError, KeyError ):
                return
            conn.flush_all()

# The PackageHub class is common for SQLObject and Dejavu
if dejavu or sqlobject:

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
                dburi = config.get("sqlobject.dburi", None)
            if not dburi:
                raise KeyError, "No database configuration found!"
            if isinstance( dburi, dict ) and dburi.has_key("__notrans__"):
                trans = False
            elif not isinstance( dburi, dict ) and dburi.startswith("notrans_"):
                dburi = dburi[8:]
                trans = False
            else:
                trans = True
            uri_hash = ( dburi, id( dburi ) )[ isinstance( dburi, dict ) ]
            hub = _hubs.get( uri_hash, None )
            if not hub:
                hub = AutoConnectHub(dburi, supports_transactions=trans)
                _hubs[uri_hash] = hub
            self.hub = hub

else:
    class AutoConnectHub(object):
        pass

    class PackageHub(object):
        pass

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
            {"sqlobject.dburi" : dburi}
        })

def commit_all():
    """Commit the transactions in all registered hubs (for this thread)."""
    for hub in hub_registry:
        hub.commit()

def rollback_all():
    """Rollback the transactions in all registered hubs (for this thread)."""
    for hub in hub_registry:
        hub.rollback()

def end_all():
    """End the transactions in all registered hubs (for this thread)."""
    for hub in hub_registry:
        hub.end()

@abstract()
def run_with_transaction(func, *args, **kw):
    pass

@abstract()
def restart_transaction(args):
    pass

def _use_sa(args=None):
    return _using_sa

# include "args" to avoid call being pre-cached
@when(run_with_transaction, "not _use_sa(args)")
def so_rwt(func, *args, **kw):
    log.debug("Starting SQLObject transaction")
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
            # No need to "rollback" the sqlalchemy unit of work,
            # because nothing has hit the db yet.
            rollback_all()
            raise
    finally:
        end_all()

# include "args" to avoid call being pre-cached
@when(restart_transaction, "not _use_sa(args)")
def so_restart_transaction(args):
    #log.debug("ReStarting SQLObject transaction")
    # Disable for now for compatibility
    pass

def dispatch_exception(exception, args, kw):
    # errorhandling import here to avoid circular imports
    from turbogears.errorhandling import dispatch_error
    # Keep in mind func is not the real func but _expose
    real_func, accept, allow_json, controller = args[:4]
    args = args[4:]
    exc_type, exc_value, exc_trace = sys.exc_info()
    remove_keys(kw, ("tg_source", "tg_errors", "tg_exceptions"))
    try:
        output = dispatch_error(
            controller, real_func, None, exception, *args, **kw)
    except NoApplicableMethods:
        raise exc_type, exc_value, exc_trace
    else:
        del exc_trace
        return output

# include "args" to avoid call being pre-cached
@when(run_with_transaction, "_use_sa(args)")
def sa_rwt(func, *args, **kw):
    log.debug("Starting SA transaction")
    request = cherrypy.request
    request.sa_transaction = session.begin()
    try:
        try:
            retval = func(*args, **kw)
        except (cherrypy.HTTPRedirect, cherrypy.InternalRedirect):
            # If a redirect happens, commit and proceed with redirect.
            if sa_transaction_active(request.sa_transaction):
                log.debug('Redirect in active transaction - will commit now')
                session.commit()
            else:
                log.debug('Redirect in inactive transaction')
            raise
        except:
            # If any other exception happens, rollback and re-raise error
            if sa_transaction_active(request.sa_transaction):
                log.debug('Error in active transaction - will rollback now')
                session.rollback()
            else:
                log.debug('Error in inactive transaction')
            raise
        # If the call was successful, commit and proceed
        if sa_transaction_active(request.sa_transaction):
            log.debug('Transaction is still active - will commit now')
            session.commit()
        else:
            log.debug('Transaction is already inactive')
    finally:
        log.debug('Ending SA transaction')
        session.close()
    return retval

# include "args" to avoid call being pre-cached
@when(restart_transaction, "_use_sa(args)")
def sa_restart_transaction(args):
    log.debug("Restarting SA transaction")
    request = cherrypy.request
    if sa_transaction_active(request.sa_transaction):
        log.debug('Transaction is still active - will rollback now')
        session.rollback()
    else:
        log.debug('Transaction is already inactive')
    session.close()
    request.sa_transaction = session.begin()

def sa_transaction_active(transaction):
    """Check whether SA transaction is still active."""
    try:
        return transaction and transaction.is_active
    except AttributeError: # SA < 0.4.3
        return transaction.session.transaction

def so_to_dict(sqlobj):
    """Convert SQLObject to a dictionary based on columns."""
    d = {}
    if sqlobj == None:
        # stops recursion
        return d
    for name in sqlobj.sqlmeta.columns.keys():
        d[name] = getattr(sqlobj, name)
    "id must be added explicitly"
    d["id"] = sqlobj.id
    if sqlobj._inheritable:
        d.update(so_to_dict(sqlobj._parent))
        d.pop('childName')
    return d

def so_columns(sqlclass, columns=None):
    """Return a dict with all columns from a SQLObject.

    This includes the columns from InheritableSO's bases.

    """
    if columns is None:
        columns = {}
    columns.update(filter(lambda i: i[0] != 'childName',
                          sqlclass.sqlmeta.columns.items()))
    if sqlclass._inheritable:
        so_columns(sqlclass.__base__, columns)
    return columns

def so_joins(sqlclass, joins=None):
    """Return a list with all joins from a SQLObject.

    The list includes the columns from InheritableSO's bases.

    """
    if joins is None:
        joins = []
    joins.extend(sqlclass.sqlmeta.joins)
    if sqlclass._inheritable:
        so_joins(sqlclass.__base__, joins)
    return joins

def dj_to_dict(unit):
    """Converts a Dejavu unit to a dictionary based on columns"""
    return dict( zip( unit.properties, [ getattr( unit, property ) for property in unit.properties ] ) )

class EndTransactionsFilter(BaseFilter):
    def on_end_resource(self):
        if _use_sa():
            session.clear()
        end_all()

__all__ = ["metadata", "session", "mapper",
           "get_engine", "get_metadata", "bind_metadata", "create_session",
           "PackageHub", "AutoConnectHub", "set_db_uri",
           "commit_all", "rollback_all", "end_all", "so_to_dict",
           "so_columns", "so_joins", "dj_to_dict", "EndTransactionsFilter"]
