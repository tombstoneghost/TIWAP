db = db.getSiblingDB("TIWAP");

db.createCollection('users');

db.users.insertMany([
    {
        username: 'admin',
        password: '21232f297a57a5a743894a0e4a801fc3'
    },
    {
        username: 'john',
        password: '6e0b7076126a29d5dfcbd54835387b7b'
    }
])

