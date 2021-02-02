from tensorflow import keras, saved_model
# from data import data
from models import get_cnn_model
# from trainer import trainer

def main():

    image_width = 300
    image_height = 300
    channels_count = 3
    number_of_categories = 10

    input_shape = (image_width, image_height, channels_count)
    model = get_cnn_model(input_shape, number_of_categories)
    
    model.compile(
        optimizer=keras.optimizers.Adam(),
        loss=keras.losses.SparseCategoricalCrossentropy(from_logits=True),
        metrics=["accuracy"]
    )

    model.fit()

if __name__ == '__main__':
    main()