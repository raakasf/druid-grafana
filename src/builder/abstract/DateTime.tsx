import React, { ChangeEvent } from 'react';
import { InlineLabel, useStyles2 } from '@grafana/ui';
import { GrafanaTheme2 } from '@grafana/data';
import { QueryBuilderFieldProps } from './types';
import { onBuilderChange } from '.';
import { css, cx } from '@emotion/css';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';


interface Props extends QueryBuilderFieldProps {
  format: string;
  time: boolean;
}

const useDate = (value = ''): any => {
  let date: Date | undefined = undefined;
  let datePlaceholder: string | undefined = undefined;
  const d = new Date(value);
  if (d instanceof Date && !isNaN(d.getFullYear())) {
    date = d;
  } else {
    datePlaceholder = value;
  }
  return [date, datePlaceholder];
};

export const DateTime = (props: Props) => {
  const [date, datePlaceholder] = useDate(props.options.builder);
  const onDateChangeRaw = (event: ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    if (value && value.indexOf('$') !== -1) {
      onBuilderChange(props, value);
    }
  };
  const onDateChange = (date: Date) => {
    onBuilderChange(props, date.toISOString());
  };
  const { label, description, format, time } = props;
  const styles = useStyles2(getStyles);
  return (
    <>
      <InlineLabel tooltip={description} width="auto">
        {label}
      </InlineLabel>
      <DatePicker
        selected={date}
        placeholderText={datePlaceholder}
        onChangeRaw={onDateChangeRaw}
        onChange={onDateChange}
        showTimeSelect={time}
        dateFormat={format}
        wrapperClassName={cx(styles.picker)}
      />
    </>
  );
};

const getStyles = (theme: GrafanaTheme2) => ({
  picker: css`
    & input {
      border: 1px solid ${theme.colors.border.medium};
      height: 32px;
      margin-right: 4px;
    }
    .react-datepicker__triangle {
      display: none;
    }
    .react-datepicker-popper {
      z-index: 1000 !important;
    }
  `,
});
