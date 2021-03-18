import React, { FC, ChangeEvent } from 'react';
import { css } from 'emotion';
import { FieldSet, Field, Switch } from '@grafana/ui';
import { ConnectionSettingsProps } from './types';
import { DruidBasicAuthSettings } from './';

export const DruidAuthSettings: FC<ConnectionSettingsProps> = (props: ConnectionSettingsProps) => {
  const { options, onOptionsChange } = props;
  const { settings } = options;

  const onSettingChange = (event: ChangeEvent<HTMLInputElement>) => {
    settings.basicAuth = event!.currentTarget.checked;
    onOptionsChange({ ...options, settings: settings });
  };

  return (
    <>
      <FieldSet
        label="Authentication"
        className={css`
          width: 300px;
        `}
      >
        <Field horizontal label="With basic authentication" description="Enable HTTP Basic authentication">
          <Switch value={settings.basicAuth} onChange={onSettingChange} css />
        </Field>
      </FieldSet>
      {settings.basicAuth && (
        <>
          <DruidBasicAuthSettings {...props} />
        </>
      )}
    </>
  );
};
