import { extend } from 'flarum/extend';
import app from 'flarum/app';

import JwtSettingsModal from './components/JwtSettingsModal';

app.initializers.add('coldsnake-jwt-auth', () => {
  app.extensionSettings['coldsnake-jwt-auth'] = () => app.modal.show(new JwtSettingsModal());
});
