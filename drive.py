from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import os
import time
gauth = GoogleAuth()
gauth.settings['oauth_scope'] = ['https://www.googleapis.com/auth/drive']
gauth.settings['client_config_file'] = './client_secret.json'

drive = GoogleDrive(gauth)

def upload_file(file):
    
    file_toUpload = drive.CreateFile({'title':file.filename})
    file.save(file.filename)
    file_toUpload.SetContentFile(file.filename)
    file_toUpload['type'] = 'anyone'
    file_toUpload['writersCanShare'] = True
    file_toUpload.Upload()
 
    
    permission = file_toUpload.InsertPermission({
    'type': 'anyone',
    'value': None,
    'role': 'reader'
})
    file_toUpload.Upload()
    print(file_toUpload.get('webContentLink'))
    return file_toUpload.get('webContentLink')

"""  if upload_comment == 'submit':
            text = request.form.get('text')
            save_comment(current_user.username, text, current_user.photo, post=) """
