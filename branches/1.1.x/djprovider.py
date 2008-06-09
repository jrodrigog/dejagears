import datetime
import dejavu
import turbogears.database
from turbogears.identity.soprovider import to_db_encoding, encrypt_password
from turbojson.jsonify import jsonify
import logging
from turbogears.util import load_class
from turbogears import identity
from dejavu import Unit, UnitProperty, UnitSequencer, UnitSequencerInteger, TriggerProperty
from turbogears.database import PackageHub
import turbogears

hub = PackageHub("turbogears.identity")
__connection__ = hub

log = logging.getLogger("identity")

try:
    set, frozenset
except NameError:
    from sets import Set as set, ImmutableSet as frozenset

# Global class references -- these will be set when the Provider is initialised.
user_class= None
group_class= None
permission_class= None
visit_class = None
# classes added
user_group_class = None
group_permission_class = None

class DejavuIdentity(object):
    """Identity that uses a model from a database (via Dejavu)."""
    def __init__(self, visit_key=None, user=None):
        self.visit_key = visit_key
        if user:
            self._user = user
            if visit_key is not None:
                self.login()

    @property
    def user(self):
        """Get user instance for this identity."""
        global hub, user_class
        try:
            return self._user
        except AttributeError:
            pass
        # Attempt to load the user. After this code executes, there *will* be
        # a _user attribute, even if the value is None.
        visit = self.visit_link
        if visit:
            box = hub.getConnection()
            box.start( isolation = turbogears.database.READ_COMMITTED )
            self._user = box.unit( user_class, user_id = visit.user_id )
            box.flush_all()
            if self._user == None:
                log.warning( "No such user with ID: %s", visit.user_id )
        else:
            self._user = None
        return self._user

    @property
    def user_name(self):
        """Get user name of this identity."""
        if not self.user:
            return None
        return self.user.user_name

    @property
    def user_id(self):
        """Get user id of this identity."""
        if not self.user:
            return None
        return self.user.user_id

    @property
    def anonymous(self):
        """Return true if not logged in."""
        return not self.user

    @property
    def permissions(self):
        """Get set of permission names of this identity."""
        try:
            return self._permissions
        except AttributeError:
            # Permissions haven't been computed yet
            pass
        if not self.user:
            self._permissions= frozenset()
        else:
            box = hub.getConnection()
            box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
            self._permissions = frozenset( p.permission_name for p in self.user.permissions )
            box.flush_all()
        return self._permissions

    @property
    def groups(self):
        """Get set of group names of this identity."""
        try:
            return self._groups
        except AttributeError:
            # Groups haven't been computed yet
            pass
        if not self.user:
            self._groups= frozenset()
        else:
            box = hub.getConnection()
            box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
            self._groups = frozenset( g.group_name for g in self.user.groups )
            box.flush_all()
        return self._groups

    @property
    def group_ids(self):
        """Get set of group IDs of this identity."""
        try:
            return self._group_ids
        except AttributeError:
            # Group ids haven't been computed yet
            pass
        if not self.user:
            self._group_ids= frozenset()
        else:
            box = hub.getConnection()
            box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
            self._group_ids = frozenset( g.group_id for g in self.user.groups )
            box.flush_all()
        return self._group_ids

    @property
    def visit_link(self):
        """Get the visit link to this identity."""
        if self.visit_key is None:
            return None
        return visit_class.by_visit_key(self.visit_key)

    def login(self):
        """Set the link between this identity and the visit."""
        visit = self.visit_link
        box = hub.getConnection()
        box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
        if visit:
            visit = box.unit( visit_class, visit_key = visit.visit_key )
            visit.user_id = self._user.user_id
        else:
            visit = visit_class( visit_key = self.visit_key, user_id = self._user.user_id )
            box.memorize( visit )
        box.flush_all()

    def logout(self):
        """Remove the link between this identity and the visit."""
        if self.visit_key != None:
            box = hub.getConnection()
            box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
            visit = box.unit( visit_class, visit_key = self.visit_key )
            if visit: visit.forget()
            box.flush_all()
        # Clear the current identity
        identity.set_current_identity( DejavuIdentity() )

    
class DejavuIdentityProvider(object):
    
    def __init__(self):
        global user_class, group_class, permission_class, visit_class, user_group_class, group_permission_class
        super(DejavuIdentityProvider, self).__init__()
        get=turbogears.config.get

        user_class_path= get( "identity.djprovider.model.user", 
                              __name__ + ".TG_User" )
        user_class= load_class(user_class_path)
        if user_class:
            log.info("Succesfully loaded \"%s\"" % user_class_path)
        try:
            self.user_class_db_encoding= \
                user_class.sqlmeta.columns['user_name'].dbEncoding
        except (KeyError, AttributeError):
            self.user_class_db_encoding= 'UTF-8'
        group_class_path= get( "identity.djprovider.model.group",
                                __name__ + ".TG_Group" )
        group_class= load_class(group_class_path)
        if group_class:
            log.info("Succesfully loaded \"%s\"" % group_class_path)
            
        permission_class_path= get( "identity.djprovider.model.permission",
                                    __name__ + ".TG_Permission" )
        permission_class= load_class(permission_class_path)
        if permission_class:
            log.info("Succesfully loaded \"%s\"" % permission_class_path)
        
        visit_class_path= get( "identity.djprovider.model.visit",
                                __name__ + ".TG_VisitIdentity" )
        visit_class= load_class(visit_class_path)
        if visit_class:
            log.info("Succesfully loaded \"%s\"" % visit_class_path)
        
        # added classes
        visit_user_group_path= get( "identity.djprovider.model.visit",
                                __name__ + ".TG_UserGroup" )
        user_group_class= load_class(visit_user_group_path)
        if user_group_class:
            log.info("Succesfully loaded \"%s\"" % visit_user_group_path)

        visit_group_permission_path= get( "identity.djprovider.model.visit",
                                __name__ + ".TG_GroupPermission" )
        group_permission_class= load_class(visit_group_permission_path)
        if group_permission_class:
            log.info("Succesfully loaded \"%s\"" % visit_group_permission_path)

            
        # Default encryption algorithm is to use plain text passwords
        algorithm = get("identity.djprovider.encryption_algorithm", None)
        self.encrypt_password = lambda pw: \
                                    identity._encrypt_password(algorithm, pw)
            
    def create_provider_model( self ):
        global user_class, group_class, permission_class, visit_class, user_group_class, group_permission_class
        # create the database tables
        try:
            arena = hub.getConnection().arena
            classes = [ user_class, group_class, permission_class, visit_class, user_group_class, group_permission_class ]
            for klass in classes:
                if not arena._registered_classes.has_key( klass ):
                    arena.register( klass )
                    if not arena.has_storage( klass ):
                        arena.create_storage( klass )
        except Exception, e:
            log.warning( "No database is configured: DejavuIdentityProvider is disabled. " + str( e ) )

    def validate_identity( self, user_name, password, visit_key ):
        box = hub.getConnection()
        box.start( isolation = dejavu.storage.isolation.REPEATABLE_READ )
        user_name = to_db_encoding( user_name, self.user_class_db_encoding )
        user = box.unit( user_class, user_name = user_name )
        if user:
            if not self.validate_password( user, user_name, password ):
                log.info( "Passwords don't match for user: %s", user_name )
                ret = None
            else:
                # Link the user to the visit
                link = box.unit( visit_class, visit_key = visit_key )
                if link:
                    link.user_id = user.user_id
                else:
                    link = visit_class( visit_key = visit_key, user_id = user.user_id )
                    box.memorize( link )
                ret = DejavuIdentity( visit_key, user )
        else:
            log.warning( "No such user: %s", user_name )
            ret = None
        box.flush_all()
        return ret

    def validate_identity(self, user_name, password, visit_key):
        """Validate the identity represented by user_name using the password.

        Must return either None if the credentials weren't valid or an object
        with the following properties:
            user_name: original user name
            user: a provider dependant object (TG_User or similar)
            groups: a set of group names
            permissions: a set of permission names

        """
        ret = None
        user_name = to_db_encoding(user_name, self.user_class_db_encoding)
        box = hub.getConnection()
        box.start( isolation = dejavu.storage.isolation.READ_COMMITTED )
        user = box.unit( user_class, user_name = user_name )
        if user:
            if not self.validate_password(user, user_name, password):
                log.info("Passwords don't match for user: %s", user_name)
                return None
            log.info("Associating user (%s) with visit (%s)",
                user_name, visit_key)
            ret = DejavuIdentity(visit_key, user)
        else:
            log.warning("No such user: %s", user_name)
        box.flush_all()
        return ret

    def validate_password(self, user, user_name, password):
        """Check the user_name and password against existing credentials.

        Note: user_name is not used here, but is required by external
        password validation schemes that might override this method.
        If you use SqlObjectIdentityProvider, but want to check the passwords
        against an external source (i.e. PAM, a password file, Windows domain),
        subclass SqlObjectIdentityProvider, and override this method.

        """
        return user.password == self.encrypt_password(password)

    def load_identity( self, visit_key ):
        """Lookup the principal represented by user_name.

        Return None if there is no principal for the given user ID.

        Must return an object with the following properties:
            user_name: original user name
            user: a provider dependant object (TG_User or similar)
            groups: a set of group names
            permissions: a set of permission names

        """
        return DejavuIdentity( visit_key )

    def anonymous_identity( self ):
        """Return anonymous identity.

        Must return an object with the following properties:
            user_name: original user name
            user: a provider dependant object (TG_User or similar)
            groups: a set of group names
            permissions: a set of permission names

        """
        return DejavuIdentity( None )

    def authenticated_identity(self, user):
        """Constructs Identity object for users with no visit_key."""
        return DejavuIdentity( user = user )

class TG_Group(Unit):
    group_id = UnitProperty( int )
    group_name = UnitProperty( unicode, index=True, hints={"bytes":16} )
    display_name = UnitProperty( unicode, hints={"bytes":255} )
    created = UnitProperty( datetime.datetime )
    ID = None
    identifiers = ("group_id",)
    sequencer = UnitSequencerInteger()
    
    def get_users( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            group_class + user_group_class + user_class,
            lambda g,up,u: g.group_id == self.group_id ) ] )
    users = property( get_users )
    
    def get_permissions( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            group_class + group_permission_class + permission_class,
            lambda g,gp,p: g.group_id == self.group_id ) ] )
    permissions = property( get_permissions )

@jsonify.when( "isinstance(obj, TG_Group)" )
def jsonify_group(obj):
    result = turbogears.database.so_to_dict( obj )
    result["users"] = [ u.user_name for u in obj.users ]
    result["permissions"] = [ p.permission_name for p in obj.permissions ]
    return result

class PasswordProperty( TriggerProperty ):
    def on_set( self, unit, old_value ):
        cleartext_password = unit.password
        "Runs cleartext_password through the hash algorithm before saving."
        try:
            hash = identity.current_provider.encrypt_password(cleartext_password)
        except identity.exceptions.IdentityManagementNotEnabledException:
            # Creating identity provider just to encrypt password
            # (so we don't reimplement the encryption step).
            ip = DejavuProvider()
            hash = ip.encrypt_password(cleartext_password)
            if hash == cleartext_password:
                log.info("Identity provider not enabled, and no encryption algorithm "
                        "specified in config.  Setting password as plaintext.")
            unit.password = hash


class TG_User(Unit):
    user_id = UnitProperty( int )
    user_name = UnitProperty( unicode, index=True, hints = { "bytes":16 } )
    email_address = UnitProperty( unicode, index=True, hints = { "bytes":255 } )
    display_name = UnitProperty( unicode, hints = { "bytes":255 } )
    password = PasswordProperty( unicode, hints = { "bytes":40 } )
    created = UnitProperty( datetime.datetime )
    ID = None
    identifiers = ("user_id",)
    sequencer = UnitSequencerInteger()

    @property
    def permissions( self ):
        permissions = set()
        for user, user_group, group, group_permission, permission in self.sandbox.recall(
            user_class + user_group_class + group_class + group_permission_class + permission_class,
            lambda u,ug,g,gp,p: u.user_id == self.user_id ):
            permissions = permissions | set( [ permission ] )
        return permissions

    @property
    def groups( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            user_class + user_group_class + group_class,
            lambda u,ug,g: u.user_id == self.user_id ) ] )

    def set_password_raw( self, password ):
        "Saves the password as-is to the database."
        raise NotImplementedError

@jsonify.when( "isinstance(obj, TG_User)" )
def jsonify_user( obj ):
    result = turbogears.database.so_to_dict( obj )
    del result["password"]
    result["groups"] = [ g.group_name for g in obj.groups ]
    result["permissions"] = [ p.permission_name for p in obj.permissions ]
    return result

class TG_Permission( Unit ):
    permission_id = UnitProperty( int )
    permission_name = UnitProperty( unicode, index = True, hints = {"bytes":16 } )
    description = UnitProperty( unicode, hints = { "bytes":255 } )
    ID = None
    identifiers = ("permission_id",)
    sequencer = UnitSequencerInteger()

    @property
    def get_groups( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            permission_class + group_permission_class + group_class,
            lambda p,gp,g: p.permission_id == self.permission_id ) ] )

@jsonify.when( "isinstance(obj, TG_Permission)" )
def jsonify_permission(obj):
    result = turbogears.database.so_to_dict( obj )
    result["groups"] = [ g.group_name for g in obj.groups ]
    return result

class TG_VisitIdentity(Unit):
    visit_key = UnitProperty( str, hints={ "bytes":40 } )
    user_id = UnitProperty( int )
    ID = None
    identifiers = ( "visit_key", )
    sequencer = UnitSequencer()
    @classmethod
    def by_visit_key( cls, key ):
        global hub, visit_class
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        visit = box.unit( visit_class, visit_key = key )
        box.flush_all()
        return visit
TG_VisitIdentity.many_to_one( "user_id", TG_User, "user_id" )

class TG_UserGroup( Unit ):
    user_id = UnitProperty( int )
    group_id = UnitProperty( int )
    ID = None
    identifiers = ( "user_id", "group_id" )
    sequencer = UnitSequencer()
TG_UserGroup.many_to_one( "user_id", TG_User, "user_id" )
TG_UserGroup.many_to_one( "group_id", TG_Group, "group_id" )

class TG_GroupPermission( Unit ):
    permission_id = UnitProperty( int )
    group_id = UnitProperty( int )
    ID = None
    identifiers = ( "permission_id", "group_id" )
    sequencer = UnitSequencer()
TG_GroupPermission.many_to_one( "permission_id", TG_Permission, "permission_id" )
TG_GroupPermission.many_to_one( "group_id", TG_Group, "group_id" )

