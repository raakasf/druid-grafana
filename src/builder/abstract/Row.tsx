import React, { ReactNode } from 'react';
import { InlineFieldRow, useStyles2 } from '@grafana/ui';
import { GrafanaTheme2 } from '@grafana/data';
import { css, cx } from '@emotion/css';

interface Props {
  children: ReactNode | ReactNode[];
}

export const Row = (props: Props) => {
  const styles = useStyles2(getStyles);
  return <InlineFieldRow className={cx(styles.row)}>{props.children}</InlineFieldRow>;
};

const getStyles = (theme: GrafanaTheme2) => ({
  row: css`
    width: 100%;
    padding-bottom: 5px;
    & > & {
      border-left: 1px solid ${theme.colors.border.medium};
      padding: 5px 0 5px 10px;
    }
  `,
});
