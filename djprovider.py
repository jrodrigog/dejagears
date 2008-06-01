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
from soprovider import DeprecatedAttr
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
    def __init__(self, visit_key, user=None):
        if user:
            self._user= user
        self.visit_key= visit_key
    
    def _get_user(self):
        try:
            return self._user
        except AttributeError:
            pass
        box = hub.getConnection()
        box.start( isolation = turbogears.database.READ_COMMITTED )
        visit = box.unit( visit_class << user_class, lambda v,u: v.visit_key == self.visit_key )
        if visit:
            if visit[1].user_id == None:
                self._user = None
                log.warning( "No such user with ID: %s", visit.user_id )
            else:
                self._user = visit[1]
        else:
            self._user = None
        box.flush_all()
        return self._user
    user= property(_get_user)
    
    def _get_user_name(self):
        if not self.user:
            return None
        return self.user.user_name
    user_name= property(_get_user_name)

    def _get_anonymous(self):
        return not self.user
    anonymous= property(_get_anonymous)
    
    def _get_permissions(self):
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
            self._permissions = frozenset( [ p.permission_name for p in self.user.permissions ] )
            box.flush_all()
        return self._permissions
    permissions= property(_get_permissions)
    
    def _get_groups(self):
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
            self._groups = frozenset( [ g.group_name for g in self.user.groups ] )
            box.flush_all()
        return self._groups
    groups= property(_get_groups)

    def logout(self):
        '''
        Remove the link between this identity and the visit.
        '''
        if self.visit_key != None:
            box = hub.getConnection()
            box.start( isolation = dejavu.storage.isolation.READ_COMMITED )
            visit = box.unit( visit_class, visit_key = self.visit_key )
            if visit: visit.forget()
            box.flush_all()
        # Clear the current identity
        anon = DejavuIdentity(None,None)
        #XXX if user is None anonymous will be true, no need to set attr.
        #anon.anonymous= True
        identity.set_current_identity( anon )

    
class DejavuIdentityProvider(object):
    
    def __init__(self):
        super(DejavuIdentityProvider, self).__init__()
        get=turbogears.config.get
        
        global user_class, group_class, permission_class, visit_class, user_group_class, group_permission_class
        
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
        box.start( isolation = dejavu.storage.isolation.SERIALIZABLE )
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

    def validate_password(self, user, user_name, password):
        return user.password == self.encrypt_password(password)

    def load_identity( self, visit_key ):
        return DejavuIdentity( visit_key )
    
    def anonymous_identity( self ):
        return DejavuIdentity( None )

    def authenticated_identity(self, user):
        return DejavuIdentity(None, user)

class TG_Group(Unit):
    group_id = UnitProperty( int )
    group_name = UnitProperty( unicode, index=True, hints={"bytes":16} )
    display_name = UnitProperty( unicode, hints={"bytes":255} )
    created = UnitProperty( datetime.datetime )
    ID = None
    identifiers = ("group_id",)
    sequencer = UnitSequencerInteger()

    # Old names
    groupId = DeprecatedAttr( "groupId", "group_name" )
    displayName = DeprecatedAttr( "displayName", "display_name" )
    
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

def jsonify_group(obj):
    result = turbogears.database.so_to_dict( obj )
    result["users"] = [ u.user_name for u in obj.users ]
    result["permissions"] = [ p.permission_name for p in obj.permissions ]
    return result

jsonify_group = jsonify.when( "isinstance(obj, TG_Group)" )( jsonify_group )

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
    password = PasswordProperty( unicode, hints={ "bytes":40 } )
    created = UnitProperty( datetime.datetime )
    ID = None
    identifiers = ("user_id",)
    sequencer = UnitSequencerInteger()

    # Old attribute names
    userId = DeprecatedAttr( "userId", "user_name" )
    emailAddress = DeprecatedAttr( "emailAddress", "email_address" )
    displayName = DeprecatedAttr( "displayName", "display_name" )

    def get_permissions( self ):
        permissions = set()
        for user, user_group, group, group_permission, permission in self.sandbox.recall(
            user_class + user_group_class + group_class + group_permission_class + permission_class,
            lambda u,ug,g,gp,p: u.user_id == self.user_id ):
            permissions = permissions | set( [ permission ] )
        return permissions
    permissions = property( get_permissions )

    def get_groups( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            user_class + user_group_class + group_class,
            lambda u,ug,g: u.user_id == self.user_id ) ] )
    groups = property( get_groups )

    def set_password_raw( self, password ):
        "Saves the password as-is to the database."
        #self._SO_set_password(password)
        raise NotImplementedError

def jsonify_user( obj ):
    result = turbogears.database.so_to_dict( obj )
    del result["password"]
    result["groups"] = [ g.group_name for g in obj.groups ]
    result["permissions"] = [ p.permission_name for p in obj.permissions ]
    return result

jsonify_user = jsonify.when( "isinstance(obj, TG_User)" )( jsonify_user )


class TG_Permission( Unit ):
    permission_id = UnitProperty( int )
    permission_name = UnitProperty( unicode, index = True, hints = {"bytes":16 } )
    description = UnitProperty( unicode, hints = { "bytes":255 } )
    ID = None
    identifiers = ("permission_id",)
    sequencer = UnitSequencerInteger()
    
    # Old attributes
    permissionId= DeprecatedAttr( "permissionId", "permission_name" )
    
    def get_groups( self ):
        return set( [ i[2] for i in self.sandbox.recall(
            permission_class + group_permission_class + group_class,
            lambda p,gp,g: p.permission_id == self.permission_id ) ] )
    groups = property( get_groups )

def jsonify_permission(obj):
    result = turbogears.database.so_to_dict( obj )
    result["groups"] = [ g.group_name for g in obj.groups ]
    return result

jsonify_permission = jsonify.when( "isinstance(obj, TG_Permission)" )( jsonify_permission )

class TG_VisitIdentity(Unit):
    visit_key = UnitProperty( str, hints={ "bytes":40 } )
    user_id = UnitProperty( int )
    ID = None
    identifiers = ( "visit_key", )
    sequencer = UnitSequencer()
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

