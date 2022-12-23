
/*test('rerender will re-render the element', () => {
  const Greeting = props => <div>{props.message}</div>
  const {container, rerender} = render(message="hi" />)
  expect(container.firstChild).toHaveTextContent('hi')
  rerender(<Greeting message="hey" />)
  expect(container.firstChild).toHaveTextContent('hey')
})*/
import { getByTestId, render, screen } from '@testing-library/react';
// @ts-ignore
import userEvent from '@testing-library/user-event';
import React from 'react';

import { PanelData, LoadingState, DataFrame, CoreApp } from '@grafana/data';

import { DruidQueryResponseSettings } from './DruidQueryResponseSettings';

const defaultProps = {
  options: {
    settings: {

    }
  },
  onOptionsChange: () => {},
  onChange: () => {},
};

describe('PromQueryField', () => {
  beforeAll(() => {
    // @ts-ignore
    window.getSelection = () => {};
  });

  it('should run query onBlur in dashboard', async () => {
    const onOptionsChange = jest.fn();
    const { container } = render(<DruidQueryResponseSettings {...defaultProps} onOptionsChange={onOptionsChange} />);

    const input = getByTestId(container, 'code-input');
    expect(input).toBeInTheDocument();
    await userEvent.type(input, 'metric');
    input.blur();
    expect(onOptionsChange).toHaveBeenCalled();
  });
});
