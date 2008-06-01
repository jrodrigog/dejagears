from turbogears import identity, redirect
from turbogears.database import PackageHub
import dejavu
import turbogears
from turbogears import controllers, expose
from cherrypy import request, response
from dejagears.model import Page
from docutils.core import publish_parts
from turbojson import jsonify
import cherrypy
import re
import datetime
from turbogears.identity.djprovider import TG_User, TG_Group, TG_UserGroup, TG_Permission, TG_GroupPermission

from turbogears import widgets
from model import Team, Player

hub = PackageHub("dejagears")
__connection__ = hub

TEMPLATE = '''
<table xmlns:py="http://purl.org/kid/ns#" class="simpleroster" border="1">
  <tr>
    <span py:if="isinstance(fields,dict)">
      <span py:for="key in fields" py:strip="True">
        <span py:for="field in fields[key]" py:strip="True">
          <th py:content="field[0]"/>
        </span>
      </span>
    </span>
    <span py:if="isinstance(fields,list)">
      <span py:for="field in fields" py:strip="True">
        <th py:content="field[0]"/>
      </span>
    </span>
  </tr>
  <span py:if="isinstance(fields,dict)">
    <tr py:for="row in value">
      <span py:for="klass in fields" py:strip="True">
        <span py:for="table in row" py:strip="True">
          <span py:if="isinstance(table,klass)">
            <span py:for="field in fields[klass]" py:strip="True">
              <td py:content="getattr( table, field[1] )"/>
            </span>
          </span>
        </span>
      </span>
    </tr>
  </span>
  <span py:if="isinstance(fields,list)" py:strip="True">
    <tr py:for="table in value">
      <span py:for="field in fields" py:strip="True">
        <td py:content="getattr( table, field[1] )"/>
      </span>
    </tr>
  </span>
</table>
'''

class DataGrid(widgets.Widget):
  template = TEMPLATE
  params = ['fields']
  def __init__(self, fields=True, *args, **kw):
    super(DataGrid,self).__init__(*args, **kw)
    self.fields=fields

wikiwords = re.compile(r"\b([A-Z]\w+[A-Z]+\w+)")

class Root(controllers.RootController):

  @expose(template="dejagears.templates.page")
  def index(self, pagename="FrontPage" ):
    box = hub.getConnection()
    player_fields = {
      Player : [
        ('Name', 'name'),
        ('Birth Date', 'birthdate'),
        #('Team', 'team'),
        ('Points', 'points'),
      ],
      Team : [
        ('City', 'city'),
        ('NickName', 'nickname'),
      ],
    }
    team_fields = [
      ('City', 'city'),
      ('NickName', 'nickname'),
    ]
    page = box.Page(pagename=pagename)
    if page == None:
      raise turbogears.redirect("notfound", pagename = pagename)
    content = publish_parts(page.data, writer_name="html")['html_body']
    root = str(turbogears.url('/'))
    content = wikiwords.sub(r'<a href="%s\1">\1</a>' % root, content)
    return dict(
      data=content,
      page=page,
      players=box.recall(Team + Player),
      teams=box.recall(Team),
      players_widget=DataGrid(fields=player_fields),
      teams_widget=DataGrid(fields=team_fields),
    )
  
  @expose(template="dejagears.templates.edit")
  def edit(self,pagename):
    box = hub.getConnection()
    page = box.Page(pagename=pagename)
    return dict(page=page)

  @expose()
  @identity.require(identity.Any(identity.in_group("admin"),identity.has_permission("ls")))
  def save(self, pagename, data, submit):
    box = hub.getConnection() #.begin( isolation = turbogears.database.SERIALIZABLE )
    self.increment_counter()
    page = box.Page(pagename=pagename)
    if page == None:
      page = Page(pagename=pagename,data=data)
      box.memorize(page)
    page.data = data
    turbogears.flash("Changes saved!")
    raise turbogears.redirect("/", pagename=pagename)
    
  @expose()
  def default_values(self):
    "Set some default values in the database"
    
    # Add some information
    box = hub.getConnection()
    t1 = Team(city='Pittsburgh', nickname='Ferrous Metals')
    box.memorize(t1)
    t2 = Team(city='Seattle', nickname='Seagulls')
    box.memorize(t2)
    p1 = Player(name='Bob Waffleburger', birthdate=datetime.date(1982,3,2), points=21)
    box.memorize(p1)
    p2 = Player(name='Mike Handleback', birthdate=datetime.date(1975,9,25), points=10)
    box.memorize(p2)
    p1.team = t1.ID
    p2.team = t2.ID
    
    # Add a default Page
    page = Page( pagename="FrontPage", data="This is the main page, please edit it." )
    box.memorize( page )
    
    # Setup identity data 
    jrodrigo = TG_User( user_name = "jrodrigo" )
    box.memorize( jrodrigo )
    jrodrigo.password = "123"
    
    root = TG_User( user_name = "root" )
    box.memorize( root )
    root.password = "root"
    
    user = TG_Group( group_name = "user" )
    box.memorize( user )
    
    admin = TG_Group( group_name = "admin" )
    box.memorize( admin )
    
    format = TG_Permission( permission_name = "format" )
    box.memorize( format )
    ls = TG_Permission( permission_name = "ls" )
    box.memorize( ls )
    cat = TG_Permission( permission_name = "cat" )
    box.memorize( cat )
    
    o = TG_UserGroup( user_id = root.user_id, group_id = user.group_id )
    box.memorize( o )
    o = TG_UserGroup( user_id = root.user_id, group_id = admin.group_id )
    box.memorize( o )
    o = TG_UserGroup( user_id = jrodrigo.user_id, group_id = user.group_id )
    box.memorize( o )
    
    o = TG_GroupPermission( group_id = admin.group_id, permission_id = format.permission_id )
    box.memorize( o )
    o = TG_GroupPermission( group_id = user.group_id, permission_id = ls.permission_id )
    box.memorize( o )
    o = TG_GroupPermission( group_id = user.group_id, permission_id = cat.permission_id )
    box.memorize( o )
    
    return "done"

  @expose()
  def default(self, pagename):
    return self.index(pagename)

  @expose("dejagears.templates.edit")
  def notfound(self, pagename):
    page = Page(pagename=pagename, data="")
    return dict(page=page)

  @expose("dejagears.templates.pagelist")
  @expose("json")
  def pagelist(self):
    box = hub.getConnection()
    self.increment_counter()
    pages = box.recall(Page)
    pages.sort(dejavu.sort('pagename'))
    pages = [page.pagename for page in pages]
    return dict(pages=pages)

  def increment_counter(self):
    # We call acquire_lock at the beginning
    #   of the method
    cherrypy.session.acquire_lock()
    c = cherrypy.session.get('counter', 0) + 1
    cherrypy.session['counter'] = c
    return str(c)
  increment_counter.exposed = True

  def read_counter(self):
    # No need to call acquire_lock
    #   because we're only reading
    #   the session data
    c = cherrypy.session.get('counter', 0) + 1
    return str(c)
  read_counter.exposed = True
    
  @expose()
  def logout(self):
    identity.current.logout()
    raise redirect("/")
  
  @expose("json")
  def lookup( self ):
    user = identity.current.user
    print user.userId
    print user.emailAddress
    print user.displayName
    group = user.groups.pop()
    print group.groupId
    print group.displayName
    permission = user.permissions.pop()
    print permission.permissionId
    
    print permission.groups

    print group.permissions
    print group.users
    
    print user.groups
    print user.permissions
    
    return [
      jsonify.encode( identity.current.user ),
      jsonify.encode( identity.current.user.groups.pop() ),
      jsonify.encode( identity.current.user.permissions.pop() ),
    ]

  @expose("dejagears.templates.login")
  def login(self, forward_url=None, previous_url=None, *args, **kw):
  
    if not identity.current.anonymous \
        and identity.was_login_attempted() \
        and not identity.get_identity_errors():
      raise redirect(forward_url)

    forward_url=None
    previous_url= request.path
  
    if identity.was_login_attempted():
      msg=_("The credentials you supplied were not correct or "
             "did not grant access to this resource.")
    elif identity.get_identity_errors():
      msg=_("You must provide your credentials before accessing "
             "this resource.")
    else:
      msg=_("Please log in.")
      forward_url= request.headers.get("Referer", "/")
      
    response.status=403
    return dict(message=msg, previous_url=previous_url, logging_in=True,
                original_parameters=request.params,
                forward_url=forward_url)

  @expose()
  @identity.require(identity.has_permission("format"))
  def format_only(self):
      return "format_only"
  
  @expose()
  @identity.require(identity.in_group("admin"))
  def root_only(self):
      return "root_only"
  
  @expose()
  @identity.require(identity.Any(identity.has_permission("ls"),identity.has_permission("format")))
  def both(self):
      return "both"
  
  @expose()
  @identity.require(identity.All(identity.has_permission("format"),identity.in_group("user")))
  def all(self):
      return "all"
