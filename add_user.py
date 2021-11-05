from lexie_cloud.users import add_user, add_lexie_instance

add_user(
    username='test_user',password='password',lexie_url='http://127.0.0.1',api_key='noapi'
)

instance = add_lexie_instance(
    username='test_user',
    lexie_instance_name='test_instance'
)
print(instance['apikey'])