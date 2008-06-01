import dejavu, cherrypy, cPickle, logging, datetime
from dejavu import Unit, UnitProperty, UnitSequencer
from turbogears.database import PackageHub
import turbogears
from turbogears.util import load_class

hub = PackageHub("turbogears.session_filter")
__connection__ = hub

log = logging.getLogger("turbogears.session_filter")

session_class = None

class DejavuStorage:
    
    def __init__(self):
        global session_class
        session_class_path = turbogears.config.get("session_filter.storage_table", __name__ + ".TG_Session")
        session_class = load_class(session_class_path)
        arena = hub.getConnection().arena
        try:
            if not arena._registered_classes.has_key( session_class ):
                arena.register( session_class )
                if not arena.has_storage( session_class ):
                    arena.create_storage( session_class )
        except Exception, e:
            log.info( str( e ) )
    def load(self, id):
        global session_class
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        session = box.unit( session_class, key=id )
        box.flush_all()
        if not session: return None
        # Unpickle data
        data = cPickle.loads(session.data)
        return (data, session.expiration_time)
    
    def save(self, id, data, expiration_time):
        global session_class
        # Pickle data
        pickled_data = cPickle.dumps(data)
        box = hub.getConnection()
        box.start( isolation=turbogears.database.SERIALIZABLE )
        session = box.unit( session_class, key=id )
        if session: session.forget()
        session = session_class(key=id,data=pickled_data,expiration_time=expiration_time)
        box.memorize( session )
        box.flush_all()
      
    def acquire_lock(self):
        box = hub.getConnection()
        box.start( isolation=turbogears.database.SERIALIZABLE )
        box.unit( session_class, key = cherrypy.session.id )
    
    def release_lock(self):
        box = hub.getConnection()
        box.flush_all()
      
    def clean_up(self, sess):
        global session_class
        box = hub.getConnection()
        box.start( isolation=turbogears.database.SERIALIZABLE )
        now = datetime.datetime.now()
        for session in box.recall( session_class, lambda x: x.expiration_time < now ):
            sess.on_delete_session( session )
            session.forget()
        box.flush_all()

class TG_Session(Unit):
    key = UnitProperty(unicode,hints={"bytes":40})
    data = UnitProperty(str,hints={"bytes":0})
    expiration_time = UnitProperty(datetime.datetime,index=True)
    ID = None
    identifiers = ( "key", )
    sequencer = UnitSequencer()
