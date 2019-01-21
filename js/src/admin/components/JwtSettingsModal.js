import SettingsModal from 'flarum/components/SettingsModal';

export default class JwtSettingsModal extends SettingsModal {
  className() {
    return 'JwtSettingsModal Modal--small';
  }

  title() {
    return app.translator.trans('coldsnake-jwt-auth.admin.jwt_settings.title');
  }

  form() {
    return [
      <div className="Form-group">
        <label>{app.translator.trans('coldsnake-jwt-auth.admin.jwt_settings.iss_label')}</label>
        <input className="FormControl" bidi={this.setting('coldsnake-jwt-auth.iss')}/>
      </div>
    ];
  }
}
