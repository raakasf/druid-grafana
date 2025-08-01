import React, { useState } from 'react';
import { ToolbarButtonRow, ToolbarButton, Drawer } from '@grafana/ui';
import { css, cx } from '@emotion/css';
import { DruidQuery } from './types';
import { DruidQuerySettings } from './configuration/QuerySettings';
import { QuerySettingsOptions } from './configuration/QuerySettings/types';
import { DruidQueryBuilder } from './builder/';
import { QueryBuilderOptions } from './builder/types';

interface Props {
  query: DruidQuery;
  onChange: (query: DruidQuery, definition: string) => void;
}

export const VariableQueryEditor = (props: Props) => {
  const { builder, settings } = props.query;
  const builderOptions = { builder: builder || {}, settings: settings || {} };
  const settingsOptions = { settings: settings || {} };
  const onBuilderOptionsChange = (queryBuilderOptions: QueryBuilderOptions) => {
    const { query, onChange } = props;
    //todo: need to implement some kind of hook system to alter a query from modules
    if (
      queryBuilderOptions.builder !== null &&
      (queryBuilderOptions.builder.intervals === undefined ||
        (Array.isArray(queryBuilderOptions.builder.intervals.intervals) &&
          queryBuilderOptions.builder.intervals.intervals.length === 0))
    ) {
      queryBuilderOptions.builder.intervals = {
        type: 'intervals',
        intervals: ['${__from:date:iso}/${__to:date:iso}'],
      };
    }
    //workaround: https://github.com/grafana/grafana/issues/30013
    const expr = JSON.stringify(queryBuilderOptions);
    onChange({ ...query, ...queryBuilderOptions, expr: expr }, expr);
  };
  const onSettingsOptionsChange = (querySettingsOptions: QuerySettingsOptions) => {
    const { query, onChange } = props;
    //workaround: https://github.com/grafana/grafana/issues/30013
    const expr = JSON.stringify({ builder: query.builder, ...querySettingsOptions });
    onChange({ ...query, ...querySettingsOptions, expr: expr }, expr);
  };
  const [showDrawer, setShowDrawer] = useState(false);
  return (
    <>
      <ToolbarButtonRow className={cx(styles.toolbar)}>
        <ToolbarButton
          icon="cog"
          onClick={(event) => {
            setShowDrawer(true);
            event.preventDefault();
          }}
        >
          Query settings
        </ToolbarButton>
      </ToolbarButtonRow>
      {showDrawer && (
        <Drawer
          title="Settings"
          subtitle="The settings to attach to the query. Those settings will be merged with the ones defined at datasource level."
          closeOnMaskClick={true}
          scrollableContent={true}
          size="md"
          onClose={() => {
            setShowDrawer(false);
          }}
        >
          <DruidQuerySettings options={settingsOptions} onOptionsChange={onSettingsOptionsChange} />
        </Drawer>
      )}
      <DruidQueryBuilder options={builderOptions} onOptionsChange={onBuilderOptionsChange} />
    </>
  );
};

const styles = {
  toolbar: css`
    margin-bottom: 4px;
  `,
};
