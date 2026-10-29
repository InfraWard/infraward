import { BadRequestException, type PipeTransform } from '@nestjs/common';
import { LABEL, LABEL_MAX } from '../assets/labels.js';

/** Un tag en la ruta: mismo formato que los de los assets. */
export class TagParamPipe implements PipeTransform<string, string> {
  transform(value: string): string {
    if (typeof value !== 'string' || value.length > LABEL_MAX || !LABEL.test(value))
      throw new BadRequestException('Tag no válido');
    return value;
  }
}
