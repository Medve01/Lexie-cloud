from lexie_cloud.users import invitations_table
import uuid
for i in range(0,99):
    invitations_table.insert({'code': str(uuid.uuid4())})