from turbogears.database import PackageHub
import dejavu
from dejavu import UnitProperty, Unit, UnitSequencer
import datetime
import logging

hub = PackageHub("dejagears")
__connection__ = hub

class Page(Unit):
  pagename = UnitProperty(unicode,index=True,hints={"bytes":30})
  data = UnitProperty(unicode,hints={"bytes":0})

class Player(Unit):
  name = UnitProperty(unicode,index=True,hints={"bytes":40})
  birthdate = UnitProperty(datetime.date)
  team = UnitProperty(int)
  points = UnitProperty(int,hints={"default":0})

class Team(Unit):
  city = UnitProperty(str,hints={"bytes":20})
  nickname = UnitProperty(str,index=True,hints={"bytes":20})
Team.one_to_many('ID',Player,'team')


# Auto set up the database, only if it does not already exists
log = logging.getLogger("turbogears.database")
arena = hub.getConnection().arena
arena.register_all(globals())

"""
for store in arena.stores.itervalues():
  store.auto_discover = False
  try:
    # An exception here, database exists, halts all the Dejavu's system;
    # so you must create the database by hand for it to work fine.
    store.create_database()
  except Exception, e:
    pass
"""

for klass in arena._registered_classes:
  if not arena.has_storage( klass ):
      arena.create_storage( klass )
